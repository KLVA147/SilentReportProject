"""Wizard konsol saat SilentReport.bat dijalankan: (1) sambungan MySQL, (2) pembuatan dongle.

Pembuatan dongle terjadi DI SINI, pada peluncuran pertama: pengguna melihat daftar flashdisk
(nama volume, kapasitas), memilih nomor, lalu harus mengetik YA agar kunci ditulis ke drive itu.
Semua fungsi menerima input_fn/pw_fn/out agar bisa diuji otomatis.
"""
import getpass
import os

import db
from sr_crypto import dongle

LINE = "=" * 60


def _ask(prompt, default, input_fn):
    raw = input_fn("{} [{}]: ".format(prompt, default) if default != "" else prompt + ": ").strip()
    return raw or default


# ------------------------------------------------------------------ langkah 1: MySQL
def ask_mysql_settings(cfg, input_fn=input, pw_fn=getpass.getpass, out=print):
    out("\nMasukkan pengaturan MySQL (Enter = pakai nilai di dalam kurung).")
    new = dict(cfg)
    new["host"] = _ask("  Host", cfg["host"], input_fn)
    while True:
        p = _ask("  Port", cfg["port"], input_fn)
        if str(p).isdigit():
            new["port"] = int(p)
            break
        out("  Port harus angka.")
    new["user"] = _ask("  User", cfg["user"], input_fn)
    pw = pw_fn("  Password (tidak terlihat saat diketik; Enter = kosong/tidak berubah): ")
    if pw == "" and cfg["password"]:
        keep = input_fn("  Pakai password yang tersimpan? (Enter = ya, n = kosongkan): ").strip().lower()
        pw = "" if keep == "n" else cfg["password"]
    new["password"] = pw
    new["database"] = _ask("  Nama database (dibuat otomatis jika belum ada)", cfg["database"], input_fn)
    return new


def step_mysql(data_dir, database, input_fn=input, pw_fn=getpass.getpass, out=print) -> bool:
    if database.engine != "mysql":
        return True
    out(LINE)
    out(" Langkah 1: sambungan ke MySQL")
    out(LINE)
    while True:
        c = database.cfg
        out("Mencoba terhubung: {}@{}:{}/{} ...".format(c["user"], c["host"], c["port"], c["database"]))
        try:
            database.init_schema()
        except db.DbError as exc:
            out("GAGAL: {}".format(exc))
            out("  1) Ubah pengaturan MySQL")
            out("  2) Coba lagi (misalnya setelah menyalakan MySQL/XAMPP)")
            out("  3) Keluar")
            choice = input_fn("Pilih 1/2/3: ").strip()
            if choice == "1":
                database.cfg = ask_mysql_settings(c, input_fn, pw_fn, out)
                database._schema_ok = False
            elif choice == "3":
                return False
            continue
        db.save_config(data_dir, database.cfg)
        out("OK: MySQL terhubung, database '{}' dan tabel siap.".format(database.cfg["database"]))
        return True


# ------------------------------------------------------------------ langkah 2: dongle
def _print_drives(drives, out):
    out("\nFlashdisk/drive yang terdeteksi:")
    for i, d in enumerate(drives, 1):
        out("  [{}] {}   ({})".format(i, d["path"], d["detail"] or d["label"]))


def step_dongle(data_dir, database, dongle_dirs=(), input_fn=input, out=print) -> bool:
    registry = os.path.join(data_dir, "dongle.sha256")
    if os.path.exists(registry):
        return True
    out(LINE)
    out(" Langkah 2: buat dongle (kunci enkripsi pada flashdisk)")
    out(LINE)
    try:
        orphan = database.has_users()
    except Exception:
        orphan = False
    if orphan:
        out("Database sudah berisi akun, tetapi dongle tidak terdaftar di komputer ini.")
        out("Membuat kunci baru membuat data lama TIDAK BISA dibuka. Pasang flashdisk dongle lama")
        out("atau pulihkan file dongle.sha256 ke: " + data_dir)
        out("(Untuk memulai dari nol saat pengujian: python launcher.py --reset)")
        return False
    show_all = False
    while True:
        drives = dongle.removable_drives(dongle_dirs, include_all=show_all)
        if not drives:
            out("\nFlashdisk belum terdeteksi. Colok flashdisk ke komputer.")
            ans = input_fn("Tekan Enter untuk memeriksa lagi, 's' untuk menampilkan semua drive, "
                           "'k' untuk keluar: ").strip().lower()
            if ans == "k":
                return False
            show_all = show_all or ans == "s"
            continue
        _print_drives(drives, out)
        ans = input_fn("\nKetik nomor flashdisk yang dijadikan dongle, 'r' periksa ulang, "
                       "'s' tampilkan semua drive, 'k' keluar: ").strip().lower()
        if ans == "k":
            return False
        if ans == "s":
            show_all = True
            continue
        if ans == "r" or not ans.isdigit() or not 1 <= int(ans) <= len(drives):
            if ans not in ("r", ""):
                out("Pilihan tidak valid.")
            continue
        d = drives[int(ans) - 1]
        out("\nAnda memilih: {}   ({})".format(d["path"], d["detail"] or d["label"]))
        if os.path.exists(os.path.join(d["path"], dongle.KEYFILE)):
            out("PERINGATAN: drive ini SUDAH berisi file kunci SilentReport; file itu akan ditimpa.")
        out("Satu file kecil bernama {} akan ditulis ke drive ini. Isi lain tidak diubah.".format(dongle.KEYFILE))
        out("Simpan flashdisk dengan baik dan salin cadangan file kunci: jika hilang, data tidak bisa dibuka.")
        if input_fn("Ketik YA (huruf besar) untuk membuat dongle di drive ini, atau Enter untuk memilih ulang: "
                    ).strip() != "YA":
            out("Dibatalkan, silakan pilih lagi.")
            continue
        try:
            dongle.create_dongle(d["path"], registry)
        except OSError as exc:
            out("Gagal menulis ke {}: {}".format(d["path"], exc))
            continue
        out("\nDongle berhasil dibuat di {}".format(d["path"]))
        return True


def run(data_dir, database, dongle_dirs=(), input_fn=input, pw_fn=getpass.getpass, out=print) -> bool:
    if not step_mysql(data_dir, database, input_fn, pw_fn, out):
        return False
    return step_dongle(data_dir, database, dongle_dirs, input_fn, out)


def reset(data_dir, database, input_fn=input, out=print) -> bool:
    """Mulai dari nol (untuk pengujian): hapus registri dongle, kode petugas, dan database."""
    out("PERINGATAN: ini MENGHAPUS database '{}', registri dongle, dan kode petugas.".format(
        database.cfg["database"]))
    if input_fn("Ketik HAPUS untuk melanjutkan: ").strip() != "HAPUS":
        out("Dibatalkan.")
        return False
    for name in ("dongle.sha256", "officer_code.txt"):
        try:
            os.remove(os.path.join(data_dir, name))
        except OSError:
            pass
    try:
        database.drop_database()
    except db.DbError as exc:
        out("Database tidak dapat dihapus: {}".format(exc))
        return False
    out("Selesai. Jalankan lagi SilentReport.bat.")
    return True
