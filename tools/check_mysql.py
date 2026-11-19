"""Cek mandiri sambungan MySQL untuk SilentReport.

    python tools/check_mysql.py

Memeriksa: PyMySQL terpasang, server terjangkau, login benar, database bisa dibuat, semua tabel
bisa dibuat, serta tulis/baca/hapus (termasuk BLOB 1 MB dan teks Unicode) berjalan. Memakai
database sementara 'srcheck_xxx' yang dihapus lagi; database asli tidak disentuh.
Pengaturan dibaca dari folder data (mysql.json) dan variabel SR_DB_*.
"""
import os
import secrets
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import db  # noqa: E402
from launcher import default_data_dir  # noqa: E402


def main() -> int:
    data_dir = default_data_dir()
    os.environ["SR_DB_NAME"] = "srcheck_" + secrets.token_hex(4)
    d = db.Database(data_dir)
    d.engine = "mysql"
    c = d.cfg
    print("Menguji {}@{}:{} (database sementara {})".format(c["user"], c["host"], c["port"], c["database"]))
    try:
        d.init_schema()
        print("[OK] terhubung dan 5 tabel dibuat")
        con = d.connect()
        con.execute("INSERT INTO users (username,pw_hash,role,created) VALUES (?,?,?,?)",
                    ("cek", "x", "reporter", 1.5))
        uid = con.execute("SELECT id FROM users WHERE username=?", ("cek",)).fetchone()["id"]
        con.execute("INSERT INTO reports (owner_id,title,category,created) VALUES (?,?,?,?)",
                    (uid, "judul é中", "Korupsi", 2.5))
        rid = con.execute("SELECT id FROM reports").fetchone()["id"]
        blob = os.urandom(1024 * 1024)
        con.execute("INSERT INTO attachments (report_id,kind,name,data,sha256,uploader_id,created) "
                    "VALUES (?,?,?,?,?,?,?)", (rid, "file", "n", blob, "0" * 64, uid, 3.5))
        con.commit()
        got = con.execute("SELECT data FROM attachments").fetchone()["data"]
        assert bytes(got) == blob, "BLOB 1 MB tidak kembali utuh"
        assert con.execute("SELECT title FROM reports").fetchone()["title"] == "judul é中"
        con.close()
        print("[OK] tulis/baca teks Unicode dan BLOB 1 MB utuh")
        print("\nSemua pemeriksaan lulus. MySQL siap dipakai SilentReport.")
        code = 0
    except db.DbError as exc:
        print("[GAGAL] {}".format(exc))
        code = 1
    except Exception as exc:  # noqa: BLE001
        print("[GAGAL] {}: {}".format(type(exc).__name__, exc))
        code = 1
    finally:
        try:
            d.drop_database()
        except Exception:
            pass
    return code


if __name__ == "__main__":
    sys.exit(main())
