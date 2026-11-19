"""Lapisan database SilentReport: MySQL (PyMySQL) sebagai penyimpanan utama.

Semua hasil enkripsi (judul, pesan, nama file, isi file terenkripsi, template wajah, blok
blockchain) disimpan sebagai kolom biasa di MySQL, sehingga bisa dilihat dan DIUBAH langsung
lewat klien MySQL (mysql CLI, MySQL Workbench, phpMyAdmin, HeidiSQL) untuk menguji kinerja
dan ketahanan kriptografinya.

Konfigurasi koneksi (urutan prioritas: variabel lingkungan > berkas mysql.json > bawaan):
    SR_DB_HOST (127.0.0.1)  SR_DB_PORT (3306)  SR_DB_USER (root)
    SR_DB_PASSWORD ("")     SR_DB_NAME (silentreport)
    <folder data>/mysql.json  ->  {"host":..., "port":..., "user":..., "password":..., "database":...}

SR_DB_ENGINE=sqlite hanya untuk pengujian otomatis tanpa server MySQL (tidak dipakai pengguna).

Kode aplikasi menulis SQL dengan penanda '?'; adaptor mengubahnya ke '%s' untuk MySQL.
"""
import json
import os
import sqlite3

DEFAULTS = {"host": "127.0.0.1", "port": 3306, "user": "root",
            "password": "", "database": "silentreport"}


class DbError(Exception):
    """Kesalahan database yang pesannya aman/berguna ditampilkan ke pengguna."""


# --------------------------------------------------------------------------- skema
SCHEMA_MYSQL = [
    """CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(30) NOT NULL,
        pw_hash VARCHAR(255) NOT NULL,
        role VARCHAR(10) NOT NULL,
        face_template LONGTEXT NULL,
        created DOUBLE NOT NULL,
        UNIQUE KEY uq_users_username (username)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS reports (
        id INT AUTO_INCREMENT PRIMARY KEY,
        owner_id INT NOT NULL,
        title LONGTEXT NOT NULL,
        category VARCHAR(40) NOT NULL,
        status VARCHAR(20) NOT NULL DEFAULT 'baru',
        created DOUBLE NOT NULL,
        KEY ix_reports_owner (owner_id),
        CONSTRAINT fk_reports_owner FOREIGN KEY (owner_id) REFERENCES users(id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS messages (
        id INT AUTO_INCREMENT PRIMARY KEY,
        report_id INT NOT NULL,
        sender_id INT NOT NULL,
        body LONGTEXT NOT NULL,
        important TINYINT NOT NULL DEFAULT 0,
        created DOUBLE NOT NULL,
        KEY ix_messages_report (report_id),
        CONSTRAINT fk_messages_report FOREIGN KEY (report_id) REFERENCES reports(id),
        CONSTRAINT fk_messages_sender FOREIGN KEY (sender_id) REFERENCES users(id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS attachments (
        id INT AUTO_INCREMENT PRIMARY KEY,
        report_id INT NOT NULL,
        kind VARCHAR(10) NOT NULL,
        name LONGTEXT NOT NULL,
        data LONGBLOB NOT NULL,
        sha256 CHAR(64) NOT NULL,
        uploader_id INT NOT NULL,
        created DOUBLE NOT NULL,
        KEY ix_attachments_report (report_id),
        CONSTRAINT fk_att_report FOREIGN KEY (report_id) REFERENCES reports(id),
        CONSTRAINT fk_att_uploader FOREIGN KEY (uploader_id) REFERENCES users(id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS blocks (
        idx INT NOT NULL PRIMARY KEY,
        ts DOUBLE NOT NULL,
        data LONGTEXT NOT NULL,
        prev_hash CHAR(64) NOT NULL,
        nonce BIGINT NOT NULL,
        hash CHAR(64) NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
]

SCHEMA_SQLITE = [
    """CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
        pw_hash TEXT NOT NULL, role TEXT NOT NULL, face_template TEXT, created REAL NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER NOT NULL REFERENCES users(id),
        title TEXT NOT NULL, category TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'baru',
        created REAL NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT, report_id INTEGER NOT NULL REFERENCES reports(id),
        sender_id INTEGER NOT NULL REFERENCES users(id), body TEXT NOT NULL,
        important INTEGER NOT NULL DEFAULT 0, created REAL NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS attachments (
        id INTEGER PRIMARY KEY AUTOINCREMENT, report_id INTEGER NOT NULL REFERENCES reports(id),
        kind TEXT NOT NULL, name TEXT NOT NULL, data BLOB NOT NULL, sha256 TEXT NOT NULL,
        uploader_id INTEGER NOT NULL REFERENCES users(id), created REAL NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS blocks (
        idx INTEGER PRIMARY KEY, ts REAL NOT NULL, data TEXT NOT NULL, prev_hash TEXT NOT NULL,
        nonce INTEGER NOT NULL, hash TEXT NOT NULL)""",
]

TABLES = ["users", "reports", "messages", "attachments", "blocks"]


# ---------------------------------------------------------------------- konfigurasi
def config_path(data_dir: str) -> str:
    return os.path.join(data_dir, "mysql.json")


def load_config(data_dir: str) -> dict:
    cfg = dict(DEFAULTS)
    try:
        with open(config_path(data_dir), encoding="utf-8") as fh:
            cfg.update({k: v for k, v in json.load(fh).items() if k in DEFAULTS})
    except (OSError, ValueError):
        pass
    env = {"host": "SR_DB_HOST", "port": "SR_DB_PORT", "user": "SR_DB_USER",
           "password": "SR_DB_PASSWORD", "database": "SR_DB_NAME"}
    for key, var in env.items():
        if var in os.environ:
            cfg[key] = os.environ[var]
    cfg["port"] = int(cfg["port"])
    return cfg


def save_config(data_dir: str, cfg: dict) -> None:
    os.makedirs(data_dir, exist_ok=True)
    clean = {k: cfg[k] for k in DEFAULTS}
    with open(config_path(data_dir), "w", encoding="utf-8") as fh:
        json.dump(clean, fh, indent=2)


def _valid_dbname(name: str) -> str:
    if not name or not name.replace("_", "").isalnum() or len(name) > 64:
        raise DbError("Nama database hanya boleh huruf/angka/_ (maks. 64 karakter).")
    return name


# -------------------------------------------------------------------- adaptor seragam
class Cursor:
    def __init__(self, raw, engine):
        self._raw, self._engine = raw, engine
        self.lastrowid = getattr(raw, "lastrowid", None)

    def _row(self, r):
        return None if r is None else dict(r)

    def fetchone(self):
        return self._row(self._raw.fetchone())

    def fetchall(self):
        return [self._row(r) for r in self._raw.fetchall()]

    def __iter__(self):
        return iter(self.fetchall())


class Conn:
    def __init__(self, raw, engine):
        self._raw, self.engine = raw, engine

    def execute(self, sql, params=()):
        if self.engine == "mysql":
            sql = sql.replace("%", "%%").replace("?", "%s")
            cur = self._raw.cursor()
            cur.execute(sql, tuple(params))
        else:
            cur = self._raw.execute(sql, tuple(params))
        return Cursor(cur, self.engine)

    def commit(self):
        self._raw.commit()

    def rollback(self):
        self._raw.rollback()

    def close(self):
        try:
            self._raw.close()
        except Exception:
            pass


class Database:
    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        self.engine = "sqlite" if os.environ.get("SR_DB_ENGINE") == "sqlite" else "mysql"
        self.cfg = load_config(data_dir)
        self._schema_ok = False

    # -- koneksi
    def _pymysql(self):
        try:
            import pymysql
            import pymysql.cursors
        except ImportError as exc:
            raise DbError("Paket PyMySQL belum terpasang. Jalankan: pip install PyMySQL") from exc
        return pymysql

    def _mysql_connect(self, with_db=True):
        pymysql = self._pymysql()
        c = self.cfg
        try:
            return pymysql.connect(
                host=c["host"], port=c["port"], user=c["user"], password=c["password"],
                database=_valid_dbname(c["database"]) if with_db else None,
                charset="utf8mb4", cursorclass=pymysql.cursors.DictCursor,
                autocommit=False, connect_timeout=5)
        except pymysql.err.OperationalError as exc:
            code = exc.args[0] if exc.args else 0
            if code == 1045:
                msg = "MySQL menolak user/password (error 1045)."
            elif code == 1049:
                msg = "Database '{}' belum ada (error 1049).".format(c["database"])
            else:
                msg = "Tidak dapat terhubung ke MySQL di {}:{} ({}).".format(
                    c["host"], c["port"], exc.args[1] if len(exc.args) > 1 else exc)
            raise DbError(msg) from exc
        except pymysql.MySQLError as exc:
            raise DbError("Kesalahan MySQL: {}".format(exc)) from exc

    def connect(self) -> Conn:
        if self.engine == "mysql":
            return Conn(self._mysql_connect(), "mysql")
        raw = sqlite3.connect(os.path.join(self.data_dir, "silentreport_test.db"))
        raw.row_factory = sqlite3.Row
        raw.execute("PRAGMA foreign_keys = ON")
        return Conn(raw, "sqlite")

    # -- skema
    def create_database_if_missing(self):
        if self.engine != "mysql":
            return
        name = _valid_dbname(self.cfg["database"])
        raw = self._mysql_connect(with_db=False)
        try:
            raw.cursor().execute(
                "CREATE DATABASE IF NOT EXISTS `{}` CHARACTER SET utf8mb4 "
                "COLLATE utf8mb4_unicode_ci".format(name))
            raw.commit()
        except Exception as exc:
            raise DbError("Gagal membuat database '{}': {}. Buat manual lewat: "
                          "CREATE DATABASE {};".format(name, exc, name)) from exc
        finally:
            raw.close()

    def init_schema(self):
        self.create_database_if_missing()
        conn = self.connect()
        try:
            stmts = SCHEMA_MYSQL if self.engine == "mysql" else SCHEMA_SQLITE
            for s in stmts:
                conn.execute(s)
            conn.commit()
        except DbError:
            raise
        except Exception as exc:
            raise DbError("Gagal membuat tabel: {}".format(exc)) from exc
        finally:
            conn.close()
        self._schema_ok = True

    def ensure_schema(self):
        if not self._schema_ok:
            self.init_schema()

    def has_users(self) -> bool:
        conn = self.connect()
        try:
            return conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"] > 0
        finally:
            conn.close()

    def drop_database(self):
        """Hanya untuk pengujian: hapus seluruh database/berkas uji."""
        if self.engine == "mysql":
            name = _valid_dbname(self.cfg["database"])
            raw = self._mysql_connect(with_db=False)
            try:
                raw.cursor().execute("DROP DATABASE IF EXISTS `{}`".format(name))
                raw.commit()
            finally:
                raw.close()
        else:
            p = os.path.join(self.data_dir, "silentreport_test.db")
            if os.path.exists(p):
                os.remove(p)
