"""Tes otomatis: membuktikan 7 kriteria tugas akhir terpenuhi.

Jalankan dari folder project:   python -m unittest tests.test_criteria -v

Mesin database:
  - Bawaan: MySQL (butuh server MySQL/MariaDB + PyMySQL). Tiap tes memakai database baru bernama
    srtest_<acak> yang dihapus lagi setelah tes. Atur koneksi dengan SR_DB_HOST/PORT/USER/PASSWORD.
  - Tanpa server MySQL (mis. di CI): SR_DB_ENGINE=sqlite python -m unittest tests.test_criteria -v
    (mesin uji saja; skema dan kueri sama, hanya driver yang berbeda).
"""
import base64
import io
import os
import re
import shutil
import secrets
import sys
import tempfile
import unittest

import cv2
import numpy as np
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from PIL import Image

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import db  # noqa: E402
import firstrun  # noqa: E402
from app import create_app  # noqa: E402
from sr_crypto import blockchain, dbcrypto, dongle, keys, stego, textcrypto  # noqa: E402
from sr_crypto.classic import vigenere_decrypt  # noqa: E402
from sr_crypto import face as facemod  # noqa: E402
from tools import face_sim as sim  # noqa: E402


class Row(dict):
    """Baris hasil kueri yang bisa diakses lewat nama kolom maupun nomor kolom."""

    def __getitem__(self, k):
        return list(self.values())[k] if isinstance(k, int) else super().__getitem__(k)


def face_files(person="A", seed=0, n=5):
    """Frame 'webcam' (JPEG) sebagai berkas unggahan multipart."""
    return [(io.BytesIO(raw), "wajah{}.jpg".format(i)) for i, raw in enumerate(sim.session(person, seed, n))]


def photo_bytes(w=200, h=160, seed=0):
    rng = np.random.RandomState(seed)
    arr = rng.randint(0, 256, (h, w, 3), dtype=np.uint8)
    buf = io.BytesIO()
    Image.fromarray(arr).save(buf, format="PNG")
    return buf.getvalue()


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.data = os.path.join(self.tmp, "data")
        self.usb = os.path.join(self.tmp, "usb")
        os.makedirs(self.data)
        self._old_name = os.environ.get("SR_DB_NAME")
        os.environ["SR_DB_NAME"] = "srtest_" + secrets.token_hex(6)  # database baru per tes
        self.dbo = db.Database(self.data)
        dongle.create_dongle(self.usb, os.path.join(self.data, "dongle.sha256"))
        self.app = create_app(self.data, [self.usb])
        self.master = dongle.find_dongle(os.path.join(self.data, "dongle.sha256"), [self.usb])
        self.c = self.app.test_client()

    def tearDown(self):
        try:
            self.dbo.drop_database()
        finally:
            if self._old_name is None:
                os.environ.pop("SR_DB_NAME", None)
            else:
                os.environ["SR_DB_NAME"] = self._old_name
            shutil.rmtree(self.tmp, ignore_errors=True)

    def csrf(self, client, url="/login"):
        html = client.get(url).get_data(as_text=True)
        return re.search(r'name="csrf" value="([^"]+)"', html).group(1)

    def register(self, client, name, role="reporter", code="", face=None, person="A"):
        return client.post("/register", data={
            "csrf": self.csrf(client, "/register"), "username": name, "password": "Passw0rd!!",
            "role": role, "officer_code": code,
            "face": face if face is not None else face_files(person, 0, 5),
        }, content_type="multipart/form-data")

    def login(self, client, name, password="Passw0rd!!", face=None, person="A"):
        return client.post("/login", data={
            "csrf": self.csrf(client, "/login"), "username": name, "password": password,
            "face": face if face is not None else face_files(person, 1000, 4),
        }, content_type="multipart/form-data")

    def post(self, client, url, data, page=None):
        data = dict(data)
        data["csrf"] = self.csrf(client, page or url)
        return client.post(url, data=data, content_type="multipart/form-data")

    def newuser(self, name="pelapor1", role="reporter", code="", person="A"):
        c = self.app.test_client()
        self.register(c, name, role, code, person=person)
        self.login(c, name, person=person)
        return c

    def dbrows(self, sql, args=()):
        """Baca langsung dari MySQL (seperti membuka tabel lewat klien MySQL)."""
        con = self.dbo.connect()
        try:
            return [Row(r) for r in con.execute(sql, args).fetchall()]
        finally:
            con.close()

    def dbexec(self, sql, args=()):
        """Ubah data langsung di MySQL (simulasi manipulasi manual untuk uji kriptografi)."""
        con = self.dbo.connect()
        try:
            con.execute(sql, args)
            con.commit()
        finally:
            con.close()


class K1_DongleDanLogin(Base):
    def test_tanpa_dongle_seluruh_aplikasi_terkunci(self):
        # proses boleh menyala (menunggu dongle), tetapi TIDAK ADA fitur/data yang bisa dipakai
        locked = create_app(self.data, [os.path.join(self.tmp, "tidak_ada")]).test_client()
        for url in ("/login", "/register", "/dashboard", "/report/1", "/chain", "/att/1/download", "/inspect"):
            self.assertEqual(locked.get(url).status_code, 423, url)
        self.assertEqual(locked.get("/api/dongle").get_json()["present"], False)
        # file statis (css/js) tetap dilayani agar layar kunci tampil rapi
        self.assertEqual(locked.get("/static/css/app.css").status_code, 200)

    def test_status_dongle_berubah_otomatis(self):
        self.assertEqual(self.c.get("/api/dongle").get_json(),
                         {"app": "SilentReport", "configured": True, "present": True})
        os.remove(os.path.join(self.usb, dongle.KEYFILE))
        self.assertEqual(self.c.get("/api/dongle").get_json()["present"], False)

    def test_app_terkunci_saat_dongle_dicabut(self):
        self.assertEqual(self.c.get("/login").status_code, 200)
        os.remove(os.path.join(self.usb, dongle.KEYFILE))  # cabut dongle
        r = self.c.get("/login")
        self.assertEqual(r.status_code, 423)
        self.assertIn("Terkunci", r.get_data(as_text=True))

    def test_dongle_palsu_ditolak(self):
        fake = os.path.join(self.tmp, "usb_palsu")
        os.makedirs(fake)
        with open(os.path.join(fake, dongle.KEYFILE), "w") as fh:
            fh.write('{"secret": "%s"}' % ("ab" * 32))
        reg = os.path.join(self.data, "dongle.sha256")
        self.assertIsNone(dongle.find_dongle(reg, [fake]))

    def test_login_wajah_dan_password_lolos(self):
        self.register(self.c, "ani")
        self.assertEqual(self.login(self.c, "ani").status_code, 302)
        self.assertEqual(self.c.get("/dashboard").status_code, 200)

    def test_login_password_salah_ditolak(self):
        self.register(self.c, "ani")
        self.assertEqual(self.login(self.c, "ani", password="salahsalah").status_code, 401)

    def test_tidak_ada_lagi_fitur_sidik_jari(self):
        for url in ("/login", "/register"):
            html = self.c.get(url).get_data(as_text=True).lower()
            self.assertNotIn("sidik jari", html)
            self.assertNotIn('name="fingerprint"', html)
        self.register(self.c, "ani")
        self.assertNotIn("bio_template", self.dbrows("SELECT * FROM users")[0])


class K1b_BiometrikWajah(Base):
    def test_login_wajah_sama_lolos(self):
        self.register(self.c, "ani")
        r = self.login(self.c, "ani")
        self.assertEqual(r.status_code, 302)

    def test_wajah_orang_lain_ditolak_walau_password_benar(self):
        self.register(self.c, "ani")
        r = self.login(self.c, "ani", face=face_files("B", 2000, 4))
        self.assertEqual(r.status_code, 401)
        self.assertIn("wajah", r.get_data(as_text=True))
        self.assertEqual(self.c.get("/dashboard").status_code, 302)

    def test_tanpa_foto_wajah_ditolak(self):
        self.register(self.c, "ani")
        r = self.c.post("/login", data={"csrf": self.csrf(self.c), "username": "ani", "password": "Passw0rd!!"},
                        content_type="multipart/form-data")
        self.assertEqual(r.status_code, 400)

    def test_gambar_tanpa_wajah_ditolak_dengan_pesan_jelas(self):
        self.register(self.c, "ani")
        blank = [(io.BytesIO(photo_bytes(320, 240, seed=i)), "x.png") for i in range(3)]
        r = self.login(self.c, "ani", face=blank)
        self.assertEqual(r.status_code, 400)
        self.assertIn("Wajah tidak terdeteksi", r.get_data(as_text=True))

    def test_pesan_kualitas_wajah_tidak_membocorkan_akun(self):
        blank = lambda: [(io.BytesIO(photo_bytes(320, 240, seed=i)), "x.png") for i in range(3)]
        self.register(self.c, "ani")
        a = self.login(self.c, "ani", face=blank())
        b = self.login(self.c, "tidak_ada", face=blank())
        self.assertEqual(a.status_code, b.status_code)

    def test_registrasi_wajib_foto_wajah(self):
        r = self.c.post("/register", data={
            "csrf": self.csrf(self.c, "/register"), "username": "ani", "password": "Passw0rd!!", "role": "reporter"}, content_type="multipart/form-data")
        self.assertEqual(self.dbrows("SELECT COUNT(*) FROM users")[0][0], 0)
        self.assertIn("Foto wajah wajib", r.get_data(as_text=True))

    def test_registrasi_menolak_foto_campuran_dua_orang(self):
        mix = face_files("A", 0, 3) + face_files("B", 0, 3)
        r = self.register(self.c, "ani", face=mix)
        self.assertEqual(self.dbrows("SELECT COUNT(*) FROM users")[0][0], 0)
        self.assertIn("tidak konsisten", r.get_data(as_text=True))

    def test_registrasi_menolak_terlalu_sedikit_foto_layak(self):
        r = self.register(self.c, "ani", face=face_files("A", 0, 2))
        self.assertEqual(self.dbrows("SELECT COUNT(*) FROM users")[0][0], 0)

    def test_template_wajah_terenkripsi_dan_bukan_foto(self):
        self.register(self.c, "ani")
        raw = self.dbrows("SELECT face_template FROM users")[0][0]
        blob = base64.b64decode(raw)
        with self.assertRaises(InvalidTag):  # tanpa kunci DB tidak bisa dibuka
            AESGCM(os.urandom(32)).decrypt(blob[:12], blob[12:], b"SR-db-v1")
        sigs = facemod.template_from_bytes(base64.b64decode(dbcrypto.decrypt_field(raw, self.master)))
        self.assertEqual(len(sigs), 5)
        self.assertEqual(sigs[0].shape, (facemod.GRID ** 2, facemod.BINS))
        self.assertNotIn(b"\xff\xd8\xff", base64.b64decode(dbcrypto.decrypt_field(raw, self.master)))  # bukan JPEG

    def test_template_wajah_dikosongkan_lewat_mysql_tidak_membuka_pintu(self):
        # penyerang yang bisa menulis ke MySQL tidak boleh mendaftarkan wajahnya sendiri
        self.register(self.c, "ani")
        self.dbexec("UPDATE users SET face_template=NULL")
        self.assertEqual(self.login(self.c, "ani").status_code, 401)
        self.assertEqual(self.login(self.app.test_client(), "ani", face=face_files("B", 3000, 4)).status_code, 401)

    def test_template_wajah_diubah_lewat_mysql_ditolak_tanpa_crash(self):
        self.register(self.c, "ani")
        raw = self.dbrows("SELECT face_template FROM users")[0][0]
        self.dbexec("UPDATE users SET face_template=?", (raw[:-6] + "AAAAAA",))
        self.assertEqual(self.login(self.c, "ani").status_code, 401)

    def test_dua_orang_berbeda_tidak_tertukar(self):
        self.register(self.c, "ani")
        self.register(self.app.test_client(), "budi", person="B")
        self.assertEqual(self.login(self.app.test_client(), "budi", person="B").status_code, 302)
        self.assertEqual(self.login(self.app.test_client(), "budi", face=face_files("A", 4000, 4)).status_code, 401)


class ModulWajah(unittest.TestCase):
    def test_orang_sama_lebih_dekat_dari_orang_beda_dengan_celah_aman(self):
        tmpl = {p: facemod.enroll(sim.session(p, 0, 6)) for p in "AB"}
        asli, penipu = [], []
        for p, o in (("A", "B"), ("B", "A")):
            for k in range(5):
                asli.append(facemod.score(tmpl[p], facemod.usable_signatures(sim.session(p, 800 + k * 4, 4), 2)))
                penipu.append(facemod.score(tmpl[p], facemod.usable_signatures(sim.session(o, 900 + k * 4, 4), 2)))
        self.assertLess(max(asli), facemod.FACE_THRESHOLD)
        self.assertGreater(min(penipu), facemod.FACE_THRESHOLD)

    def test_serialisasi_template_bolak_balik(self):
        sigs = facemod.enroll(sim.session("A", 0, 5))
        back = facemod.template_from_bytes(facemod.template_to_bytes(sigs))
        self.assertEqual(len(back), len(sigs))
        self.assertLess(facemod.distance(sigs[0], back[0]), 1e-3)  # float16 hampir tanpa kehilangan

    def test_dua_wajah_dalam_satu_gambar_ditolak(self):
        import cv2

        def tile(name, size=320):  # potong sekitar wajah supaya ukurannya sebanding, seperti dua orang di depan kamera
            raw = sim.variant(name, 1, 0.0)
            x, y, side = facemod.detect(facemod._decode_gray(raw))
            c = int(side * 2.2)
            img = cv2.imdecode(np.frombuffer(raw, np.uint8), cv2.IMREAD_COLOR)
            x0, y0 = max(0, x + side // 2 - c // 2), max(0, y + side // 2 - c // 2)
            return cv2.resize(img[y0:y0 + c, x0:x0 + c], (size, size))

        ok, buf = cv2.imencode(".jpg", np.hstack([tile("A"), tile("B")]))
        with self.assertRaises(facemod.FaceError) as cm:
            facemod.extract_signature(buf.tobytes())
        self.assertIn("lebih dari satu wajah", str(cm.exception))

    def test_gambar_rusak_ditolak(self):
        with self.assertRaises(facemod.FaceError):
            facemod.extract_signature(b"bukan gambar")


class K2_LoginKriptografi(Base):
    def test_password_disimpan_sebagai_hash_scrypt(self):
        self.register(self.c, "ani")
        pw = self.dbrows("SELECT pw_hash FROM users")[0][0]
        self.assertTrue(pw.startswith("scrypt$"))
        self.assertNotIn("Passw0rd", pw)

    def test_salt_berbeda_hash_berbeda(self):
        self.register(self.c, "ani")
        self.register(self.c, "budi")
        h = [r[0] for r in self.dbrows("SELECT pw_hash FROM users")]
        self.assertNotEqual(h[0], h[1])  # password sama, hash beda karena salt


class K3_SuperEnkripsiTeks(Base):
    def test_roundtrip_unicode(self):
        t = "Pak X menerima suap Rp5.000.000 \U0001F4B8 di ruang rapat, 12/10/2026!"
        self.assertEqual(textcrypto.decrypt_text(textcrypto.encrypt_text(t, self.master), self.master), t)

    def test_dua_lapis_klasik_lalu_modern(self):
        t = "rahasia"
        tok = textcrypto.encrypt_text(t, self.master)
        raw = base64.b64decode(tok)
        # lapis modern (AES-GCM) dibuka dulu -> hasilnya BUKAN plaintext (masih lapis Vigenere)
        stage1 = AESGCM(keys.derive(self.master, "text-aes256", 32)).decrypt(raw[:12], raw[12:], b"SR-text-v1")
        self.assertNotEqual(stage1, t.encode())
        # lapis klasik (Vigenere) dibuka -> plaintext
        self.assertEqual(vigenere_decrypt(stage1, keys.derive(self.master, "text-vigenere", 16)), t.encode())

    def test_enkripsi_probabilistik(self):
        a = textcrypto.encrypt_text("sama", self.master)
        b = textcrypto.encrypt_text("sama", self.master)
        self.assertNotEqual(a, b)

    def test_data_diubah_terdeteksi(self):
        tok = bytearray(base64.b64decode(textcrypto.encrypt_text("halo", self.master)))
        tok[-1] ^= 1
        with self.assertRaises(InvalidTag):
            textcrypto.decrypt_text(base64.b64encode(bytes(tok)).decode(), self.master)

    def test_di_database_tidak_ada_plaintext(self):
        c = self.newuser()
        self.post(c, "/report/new", {"title": "Judul Rahasia XYZ", "category": "Korupsi",
                                     "message": "isi pesan unik QWERTY123"}, page="/report/new")
        row = self.dbrows("SELECT title FROM reports")[0][0]
        body = self.dbrows("SELECT body FROM messages")[0][0]
        self.assertNotIn("Judul Rahasia", row)
        self.assertNotIn("QWERTY123", body)
        self.assertIn("QWERTY123", c.get("/report/1").get_data(as_text=True))


class K4_EnkripsiFileBeda(Base):
    def test_file_chacha20_bukan_algoritma_teks(self):
        c = self.newuser()
        secret = b"%PDF-1.4 ISI DOKUMEN RAHASIA 0123456789" * 20
        self.post(c, "/report/new", {"title": "t", "category": "Korupsi", "message": "m",
                                     "evidence_file": (io.BytesIO(secret), "bukti.pdf")}, page="/report/new")
        stored = bytes(self.dbrows("SELECT data FROM attachments")[0][0])  # BLOB di MySQL
        self.assertNotIn(b"ISI DOKUMEN RAHASIA", stored)
        key = keys.derive(self.master, "file-chacha20", 32)
        self.assertEqual(ChaCha20Poly1305(key).decrypt(stored[:12], stored[12:], b"SR-file-v1"), secret)
        # kunci file BERBEDA dari kunci teks/DB, dan AES-GCM teks tidak bisa membukanya
        self.assertNotEqual(key, keys.derive(self.master, "text-aes256", 32))
        with self.assertRaises(InvalidTag):
            AESGCM(keys.derive(self.master, "text-aes256", 32)).decrypt(stored[:12], stored[12:], b"SR-text-v1")
        r = c.get("/att/1/download")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data, secret)

    def test_file_dimodifikasi_ditolak(self):
        c = self.newuser()
        self.post(c, "/report/new", {"title": "t", "category": "Korupsi", "message": "m",
                                     "evidence_file": (io.BytesIO(b"data penting" * 10), "a.txt")}, page="/report/new")
        b = bytearray(self.dbrows("SELECT data FROM attachments")[0][0])
        b[20] ^= 0xFF
        self.dbexec("UPDATE attachments SET data=? WHERE id=1", (bytes(b),))  # ubah BLOB langsung di MySQL
        self.assertEqual(c.get("/att/1/download").status_code, 500)


class K5_PesanPentingDiDatabase(Base):
    def test_pesan_penting_punya_lapisan_db(self):
        c = self.newuser()
        self.post(c, "/report/new", {"title": "t", "category": "Korupsi", "message": "pesan biasa",
                                     "important": ""}, page="/report/new")
        self.post(c, "/report/1", {"message": "PESAN PENTING SEKALI", "important": "1"})
        rows = self.dbrows("SELECT body, important FROM messages ORDER BY id")
        biasa, penting = rows[0], rows[1]
        self.assertEqual((biasa["important"], penting["important"]), (0, 1))
        # pesan biasa: langsung bisa didekripsi lapisan teks
        self.assertEqual(textcrypto.decrypt_text(biasa["body"], self.master), "pesan biasa")
        # pesan penting: lapisan teks GAGAL (masih terbungkus lapisan DB)
        with self.assertRaises(Exception):
            textcrypto.decrypt_text(penting["body"], self.master)
        inner = dbcrypto.decrypt_field(penting["body"], self.master)
        self.assertEqual(textcrypto.decrypt_text(inner, self.master), "PESAN PENTING SEKALI")
        self.assertIn("PESAN PENTING SEKALI", c.get("/report/1").get_data(as_text=True))


class K6_Steganografi(Base):
    def test_embed_extract_dan_tak_kasat_mata(self):
        cover = photo_bytes()
        msg = b"pesan rahasia: ruang 12, jam 09.00"
        out = stego.embed(cover, msg)
        self.assertEqual(stego.extract(out), msg)
        a = np.array(Image.open(io.BytesIO(cover)).convert("RGB")).astype(int)
        b = np.array(Image.open(io.BytesIO(out)).convert("RGB")).astype(int)
        self.assertLessEqual(np.abs(a - b).max(), 1)  # perubahan maks 1 level per kanal

    def test_gambar_tanpa_pesan(self):
        with self.assertRaises(stego.StegoError):
            stego.extract(photo_bytes())

    def test_kapasitas_terlampaui(self):
        with self.assertRaises(stego.StegoError):
            stego.embed(photo_bytes(10, 10), b"x" * 1000)

    def test_alur_aplikasi(self):
        c = self.newuser()
        self.post(c, "/report/new", {"title": "t", "category": "Perundungan (bullying)", "message": "m",
                                     "evidence_image": (io.BytesIO(photo_bytes(seed=5)), "foto.jpg"),
                                     "secret_note": "difoto di gedung B lantai 2"}, page="/report/new")
        stored = bytes(self.dbrows("SELECT data FROM attachments")[0][0])
        self.assertTrue(stored.startswith(b"\x89PNG"))
        r = c.get("/att/1/extract")
        self.assertEqual(r.status_code, 200)
        self.assertIn("gedung B lantai 2", r.get_data(as_text=True))
        self.assertIn("UTUH", r.get_data(as_text=True))
        self.assertEqual(c.get("/att/1/preview").mimetype, "image/png")
        # catatan rahasia tidak tampil sebagai teks biasa di file gambar
        self.assertNotIn(b"gedung B", stored)


class K7_Blockchain(Base):
    def _chain(self):
        c = self.newuser()
        self.post(c, "/report/new", {"title": "t", "category": "Korupsi", "message": "m",
                                     "evidence_file": (io.BytesIO(b"bukti" * 50), "b.txt")}, page="/report/new")
        c.get("/att/1/download")
        return c

    def test_rantai_valid_dan_berurutan(self):
        self._chain()
        blocks = [dict(r) for r in self.dbrows("SELECT * FROM blocks ORDER BY idx")]
        self.assertGreaterEqual(len(blocks), 2)
        self.assertTrue(blockchain.validate_chain(blocks)[0])
        self.assertTrue(all(b["hash"].startswith("000") for b in blocks))
        for i in range(1, len(blocks)):
            self.assertEqual(blocks[i]["prev_hash"], blocks[i - 1]["hash"])

    def test_pemalsuan_data_terdeteksi(self):
        self._chain()
        blocks = [dict(r) for r in self.dbrows("SELECT * FROM blocks ORDER BY idx")]
        blocks[0]["data"] = blocks[0]["data"].replace("DISERAHKAN", "DIHAPUS")
        ok, bad, _ = blockchain.validate_chain(blocks)
        self.assertFalse(ok)
        self.assertEqual(bad, 0)

    def test_pemalsuan_lewat_database_terdeteksi_di_halaman(self):
        c = self._chain()
        self.dbexec("UPDATE blocks SET data = REPLACE(data,'BUKTI_DIUNDUH','TIDAK_ADA') WHERE idx=1")
        self.assertIn("TIDAK VALID", c.get("/chain").get_data(as_text=True))

    def test_hash_bukti_dicatat(self):
        self._chain()
        import hashlib, json
        d = json.loads(self.dbrows("SELECT data FROM blocks WHERE idx=0")[0][0])
        self.assertEqual(d["evidence_sha256"], hashlib.sha256(b"bukti" * 50).hexdigest())


class WizardSetupDanLauncher(unittest.TestCase):
    """Alur pengguna akhir: buka aplikasi pertama kali -> pilih flashdisk -> dongle dibuat."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.data = os.path.join(self.tmp, "data")
        self.usb = os.path.join(self.tmp, "flashdisk")
        os.makedirs(self.usb)
        self._old_name = os.environ.get("SR_DB_NAME")
        os.environ["SR_DB_NAME"] = "srtest_" + secrets.token_hex(6)
        self.dbo = db.Database(self.data)
        self.app = create_app(self.data, [self.usb])
        self.c = self.app.test_client()

    def tearDown(self):
        try:
            self.dbo.drop_database()
        finally:
            if self._old_name is None:
                os.environ.pop("SR_DB_NAME", None)
            else:
                os.environ["SR_DB_NAME"] = self._old_name
            shutil.rmtree(self.tmp, ignore_errors=True)

    def csrf(self, url):
        return re.search(r'name="csrf" value="([^"]+)"', self.c.get(url).get_data(as_text=True)).group(1)

    def test_pemakaian_pertama_diarahkan_ke_setup(self):
        r = self.c.get("/login")
        self.assertEqual(r.status_code, 302)
        self.assertTrue(r.headers["Location"].endswith("/setup"))
        html = self.c.get("/setup").get_data(as_text=True)
        self.assertIn(self.usb, html)  # flashdisk muncul di daftar

    def test_setup_membuat_dongle_dan_membuka_aplikasi(self):
        r = self.c.post("/setup", data={"csrf": self.csrf("/setup"), "drive": self.usb})
        self.assertEqual(r.status_code, 302)
        self.assertTrue(os.path.exists(os.path.join(self.usb, dongle.KEYFILE)))
        self.assertTrue(os.path.exists(os.path.join(self.data, "dongle.sha256")))
        first = self.c.get("/login")  # setelah setup, aplikasi langsung terbuka
        self.assertEqual(first.status_code, 200)
        # kode undangan petugas ditampilkan SEKALI (pesan flash), lalu hilang
        self.assertIn(self.app.config["OFFICER_CODE"], first.get_data(as_text=True))
        self.assertNotIn(self.app.config["OFFICER_CODE"], self.c.get("/login").get_data(as_text=True))
        # setup tidak bisa diulang untuk menimpa kunci
        self.assertEqual(self.c.get("/setup").status_code, 302)

    def test_setup_menolak_path_di_luar_daftar_flashdisk(self):
        evil = os.path.join(self.tmp, "folder_lain")
        os.makedirs(evil)
        self.c.post("/setup", data={"csrf": self.csrf("/setup"), "drive": evil})
        self.assertFalse(os.path.exists(os.path.join(evil, dongle.KEYFILE)))
        self.assertFalse(os.path.exists(os.path.join(self.data, "dongle.sha256")))

    def test_setup_tanpa_csrf_ditolak(self):
        self.assertEqual(self.c.post("/setup", data={"drive": self.usb}).status_code, 400)

    def test_setup_menolak_bila_ada_data_tanpa_dongle(self):
        # data lama + dongle hilang: jangan buat kunci baru (data lama jadi yatim)
        self.dbo.init_schema()
        con = self.dbo.connect()
        con.execute("INSERT INTO users (username,pw_hash,role,created) VALUES ('a','x','reporter',0)")
        con.commit(); con.close()
        html = self.c.get("/setup").get_data(as_text=True)
        self.assertIn("Data lama ditemukan", html)
        self.assertNotIn('name="drive"', html)  # tidak ada form pembuatan dongle
        with self.c.session_transaction() as sess:
            token = sess["csrf"]
        self.c.post("/setup", data={"csrf": token, "drive": self.usb})  # coba paksa lewat POST
        self.assertFalse(os.path.exists(os.path.join(self.data, "dongle.sha256")))

    def test_tombol_tutup_aplikasi_nonaktif_kecuali_launcher(self):
        self.c.post("/setup", data={"csrf": self.csrf("/setup"), "drive": self.usb})
        self.assertNotIn("Tutup aplikasi", self.c.get("/login").get_data(as_text=True))
        self.assertEqual(self.c.post("/quit", data={"csrf": self.csrf("/login")}).status_code, 404)
        self.assertEqual(self.c.post("/quit", data={}).status_code, 400)  # tanpa csrf

    def test_dongle_di_drive_pilihan_wizard_pasti_ditemukan(self):
        # regresi: drive yang ditawarkan wizard harus ikut dicari saat memeriksa dongle
        mount = os.path.join(self.tmp, "mnt", "dalam", "USB1")
        reg = os.path.join(self.data, "dongle.sha256")
        orig = dongle.removable_drives
        dongle.removable_drives = lambda extra=(), include_all=False: [{"path": mount, "label": "USB1", "detail": ""}]
        try:
            dongle.create_dongle(mount, reg)
            self.assertIsNotNone(dongle.find_dongle(reg, []))  # tanpa 'extra' sama sekali
        finally:
            dongle.removable_drives = orig

    def test_tidak_ada_drive_terpilih_otomatis_bila_lebih_dari_satu(self):
        usb2 = os.path.join(self.tmp, "flashdisk2")
        os.makedirs(usb2)
        two = create_app(os.path.join(self.tmp, "d2"), [self.usb, usb2]).test_client()
        html = two.get("/setup", follow_redirects=True).get_data(as_text=True)
        self.assertIn(self.usb, html); self.assertIn(usb2, html)
        self.assertNotIn("checked", html.split("Pilih flashdisk")[1].split("</form>")[0])

    def test_launcher_folder_data_dan_probe(self):
        import launcher
        self.assertTrue(launcher.default_data_dir().lower().endswith(("silentreport",)))
        self.assertIsNone(launcher.probe(59999))  # port kosong -> tidak ada layanan


class Keamanan(Base):
    def test_post_tanpa_csrf_ditolak(self):
        self.assertEqual(self.c.post("/login", data={"username": "a"}).status_code, 400)

    def test_pelapor_lain_tidak_bisa_lihat_laporan(self):
        c1 = self.newuser("pelapor1")
        self.post(c1, "/report/new", {"title": "t", "category": "Korupsi", "message": "m",
                                      "evidence_file": (io.BytesIO(b"x" * 30), "a.txt")}, page="/report/new")
        c2 = self.newuser("pelapor2", person="B")
        self.assertEqual(c2.get("/report/1").status_code, 404)
        self.assertEqual(c2.get("/att/1/download").status_code, 404)

    def test_petugas_bisa_dan_butuh_kode(self):
        c = self.app.test_client()
        r = self.register(c, "petugas1", "officer", code="salah")
        self.assertEqual(r.status_code, 200)  # tetap di halaman registrasi
        self.assertEqual(self.dbrows("SELECT COUNT(*) FROM users")[0][0], 0)
        self.register(c, "petugas1", "officer", code=self.app.config["OFFICER_CODE"])
        self.assertEqual(self.dbrows("SELECT role FROM users")[0][0], "officer")

    def test_pelapor_tidak_bisa_buka_inspeksi_atau_ubah_status(self):
        c = self.newuser()
        self.assertEqual(c.get("/inspect").status_code, 403)

    def test_belum_login_diarahkan(self):
        self.assertEqual(self.c.get("/dashboard").status_code, 302)
        self.assertEqual(self.c.get("/report/1").status_code, 302)

    def test_alur_petugas_ubah_status_tercatat_blockchain(self):
        cp = self.newuser("pelapor1")
        self.post(cp, "/report/new", {"title": "t", "category": "Korupsi", "message": "m"}, page="/report/new")
        co = self.newuser("petugas1", "officer", code=self.app.config["OFFICER_CODE"], person="B")
        self.assertEqual(co.get("/report/1").status_code, 200)
        self.post(co, "/report/1/status", {"status": "diterima"}, page="/report/1")
        self.assertIn('st done cur">Diterima', cp.get("/report/1").get_data(as_text=True))
        acts = [r[0] for r in self.dbrows("SELECT data FROM blocks")]
        self.assertTrue(any("STATUS_DITERIMA" in a for a in acts))
        self.assertEqual(co.get("/inspect").status_code, 200)


class PenyimpananMySQL(Base):
    """Hasil enkripsi tersimpan sebagai kolom biasa di MySQL: bisa dilihat dan diubah untuk uji."""

    def _laporan(self):
        c = self.newuser()
        self.post(c, "/report/new", {"title": "Judul UJI", "category": "Korupsi", "message": "isi UJI",
                                     "important": "1"}, page="/report/new")
        return c

    def test_semua_tabel_ada_dan_kolom_ciphertext_berupa_teks_base64(self):
        c = self._laporan()
        for t in db.TABLES:
            self.dbrows("SELECT COUNT(*) FROM {}".format(t))
        for col, table in (("title", "reports"), ("body", "messages"), ("name", "attachments")):
            if table == "attachments":
                continue
            v = self.dbrows("SELECT {} FROM {}".format(col, table))[0][0]
            self.assertIsInstance(v, str)
            base64.b64decode(v, validate=True)  # bisa disalin/diedit sebagai teks di klien MySQL

    def test_ciphertext_pesan_diubah_lewat_mysql_tidak_membuat_halaman_crash(self):
        c = self._laporan()
        body = self.dbrows("SELECT body FROM messages")[0][0]
        flipped = ("A" if body[40] != "A" else "B")
        self.dbexec("UPDATE messages SET body=?", (body[:40] + flipped + body[41:],))
        r = c.get("/report/1")
        self.assertEqual(r.status_code, 200)
        self.assertIn("DATA RUSAK", r.get_data(as_text=True))

    def test_judul_diubah_lewat_mysql_terdeteksi(self):
        c = self._laporan()
        self.dbexec("UPDATE reports SET title=?", ("bukan-ciphertext-valid",))
        self.assertIn("DATA RUSAK", c.get("/dashboard").get_data(as_text=True))
        self.assertEqual(c.get("/report/1").status_code, 200)

    def test_menukar_ciphertext_antar_pesan_tetap_terbaca_hanya_dengan_kunci_benar(self):
        # pesan dengan lapisan DB tidak bisa 'dipaksa' menjadi pesan biasa lewat tampering flag
        c = self._laporan()
        self.dbexec("UPDATE messages SET important=0")  # lepas lapisan DB secara paksa
        self.assertIn("DATA RUSAK", c.get("/report/1").get_data(as_text=True))

    def test_halaman_inspeksi_menampilkan_isi_mentah_mysql(self):
        self._laporan()
        co = self.newuser("petugas1", "officer", code=self.app.config["OFFICER_CODE"], person="B")
        html = co.get("/inspect").get_data(as_text=True)
        self.assertIn("Isi mentah tabel attachments", html)
        self.assertIn("scrypt$", html)

    def test_pengubahan_blockchain_lewat_mysql_terdeteksi(self):
        c = self.newuser()
        self.post(c, "/report/new", {"title": "t", "category": "Korupsi", "message": "m",
                                     "evidence_file": (io.BytesIO(b"bukti" * 50), "b.txt")}, page="/report/new")
        self.assertGreaterEqual(len(self.dbrows("SELECT * FROM blocks")), 1)
        self.dbexec("UPDATE blocks SET nonce = nonce + 1 WHERE idx=0")
        self.assertIn("TIDAK VALID", c.get("/chain").get_data(as_text=True))

    def test_database_tidak_tersedia_menampilkan_halaman_ramah(self):
        old = {k: os.environ.get(k) for k in ("SR_DB_ENGINE", "SR_DB_PORT", "SR_DB_HOST")}
        os.environ.pop("SR_DB_ENGINE", None)
        os.environ["SR_DB_PORT"], os.environ["SR_DB_HOST"] = "1", "127.0.0.1"
        try:
            app = create_app(self.data, [self.usb])
            r = app.test_client().get("/login")
        finally:
            for k, v in old.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
        self.assertEqual(r.status_code, 503)
        self.assertIn("Database tidak tersedia", r.get_data(as_text=True))


class AdaptorDB(unittest.TestCase):
    def test_penanda_sql_diubah_untuk_mysql(self):
        calls = []

        class Cur:
            lastrowid = 7

            def execute(self, sql, params):
                calls.append((sql, params))

        class Raw:
            def cursor(self):
                return Cur()

        conn = db.Conn(Raw(), "mysql")
        cur = conn.execute("SELECT * FROM t WHERE a=? AND b LIKE '50%' AND c=?", (1, 2))
        self.assertEqual(calls[0], ("SELECT * FROM t WHERE a=%s AND b LIKE '50%%' AND c=%s", (1, 2)))
        self.assertEqual(cur.lastrowid, 7)

    def test_skema_mysql_lengkap_dan_berurutan(self):
        names = [x.split("EXISTS ")[1].split(" ")[0] for x in db.SCHEMA_MYSQL]
        self.assertEqual(names, db.TABLES)
        self.assertEqual(len(db.SCHEMA_SQLITE), len(db.SCHEMA_MYSQL))
        joined = " ".join(db.SCHEMA_MYSQL)
        self.assertIn("LONGBLOB", joined)
        self.assertNotIn("bio_template", joined)
        self.assertNotIn("AUTOINCREMENT", joined)

    def test_konfigurasi_env_mengalahkan_berkas(self):
        d = tempfile.mkdtemp()
        try:
            db.save_config(d, {"host": "h1", "port": 3307, "user": "u1", "password": "p1", "database": "d1"})
            self.assertEqual(db.load_config(d)["host"], "h1")
            os.environ["SR_DB_HOST"] = "h2"
            try:
                self.assertEqual(db.load_config(d)["host"], "h2")
                self.assertEqual(db.load_config(d)["port"], 3307)
            finally:
                del os.environ["SR_DB_HOST"]
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_nama_database_berbahaya_ditolak(self):
        with self.assertRaises(db.DbError):
            db._valid_dbname("x`; DROP DATABASE mysql; --")


class WizardKonsol(unittest.TestCase):
    """Wizard pada jendela SilentReport.bat: pengguna memilih dan mengonfirmasi flashdisk dongle."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.data = os.path.join(self.tmp, "data")
        self.usb1 = os.path.join(self.tmp, "FLASH_A")
        self.usb2 = os.path.join(self.tmp, "FLASH_B")
        os.makedirs(self.usb1)
        os.makedirs(self.usb2)
        self._old_name = os.environ.get("SR_DB_NAME")
        os.environ["SR_DB_NAME"] = "srtest_" + secrets.token_hex(6)
        self.dbo = db.Database(self.data)
        os.makedirs(self.data)
        self.dbo.init_schema()
        self.out = []
        self._orig_drives = dongle.removable_drives
        # daftar drive tetap (hanya flashdisk uji), supaya nomor pilihan deterministik di mesin mana pun
        dongle.removable_drives = lambda extra=(), include_all=False: [
            {"path": p, "label": os.path.basename(p), "detail": dongle.drive_detail(p)} for p in extra]

    def tearDown(self):
        dongle.removable_drives = self._orig_drives
        try:
            self.dbo.drop_database()
        finally:
            if self._old_name is None:
                os.environ.pop("SR_DB_NAME", None)
            else:
                os.environ["SR_DB_NAME"] = self._old_name
            shutil.rmtree(self.tmp, ignore_errors=True)

    def script(self, *answers):
        it = iter(answers)
        return lambda prompt="": next(it)

    def reg(self):
        return os.path.join(self.data, "dongle.sha256")

    def test_pilih_drive_lalu_konfirmasi_YA_membuat_kunci_hanya_di_drive_itu(self):
        ok = firstrun.step_dongle(self.data, self.dbo, [self.usb1, self.usb2],
                                  self.script("2", "YA"), self.out.append)
        self.assertTrue(ok)
        self.assertTrue(os.path.exists(os.path.join(self.usb2, dongle.KEYFILE)))
        self.assertFalse(os.path.exists(os.path.join(self.usb1, dongle.KEYFILE)))  # drive lain tidak disentuh
        self.assertIsNotNone(dongle.find_dongle(self.reg(), [self.usb2]))

    def test_tanpa_konfirmasi_YA_tidak_ada_kunci_ditulis(self):
        ok = firstrun.step_dongle(self.data, self.dbo, [self.usb1, self.usb2],
                                  self.script("1", "ya", "", "k"), self.out.append)
        self.assertFalse(ok)  # 'ya' huruf kecil bukan konfirmasi; lalu pengguna keluar
        self.assertFalse(os.path.exists(os.path.join(self.usb1, dongle.KEYFILE)))
        self.assertFalse(os.path.exists(self.reg()))

    def test_pilihan_salah_diulang_dan_keluar_aman(self):
        ok = firstrun.step_dongle(self.data, self.dbo, [self.usb1], self.script("9", "abc", "k"), self.out.append)
        self.assertFalse(ok)
        self.assertFalse(os.path.exists(self.reg()))
        self.assertTrue(any("tidak valid" in line for line in self.out))

    def test_daftar_menampilkan_semua_drive_agar_pengguna_bisa_membedakan(self):
        firstrun.step_dongle(self.data, self.dbo, [self.usb1, self.usb2], self.script("k"), self.out.append)
        text = "\n".join(self.out)
        self.assertIn(self.usb1, text)
        self.assertIn(self.usb2, text)
        self.assertIn("GB", text)  # kapasitas ikut tampil

    def test_peringatan_bila_drive_sudah_berisi_kunci(self):
        dongle.create_dongle(self.usb1, os.path.join(self.tmp, "lain.sha256"))
        firstrun.step_dongle(self.data, self.dbo, [self.usb1], self.script("1", "", "k"), self.out.append)
        self.assertTrue(any("SUDAH berisi" in line for line in self.out))

    def test_menolak_bila_database_sudah_berisi_akun_tanpa_dongle(self):
        con = self.dbo.connect()
        con.execute("INSERT INTO users (username,pw_hash,role,created) VALUES ('a','x','reporter',0)")
        con.commit(); con.close()
        ok = firstrun.step_dongle(self.data, self.dbo, [self.usb1], self.script("1", "YA"), self.out.append)
        self.assertFalse(ok)
        self.assertFalse(os.path.exists(self.reg()))

    def test_dongle_yang_sudah_ada_tidak_ditanya_lagi(self):
        dongle.create_dongle(self.usb1, self.reg())
        called = []
        ok = firstrun.step_dongle(self.data, self.dbo, [self.usb1], lambda p="": called.append(p), self.out.append)
        self.assertTrue(ok)
        self.assertEqual(called, [])

    def test_reset_butuh_ketik_HAPUS(self):
        dongle.create_dongle(self.usb1, self.reg())
        self.assertFalse(firstrun.reset(self.data, self.dbo, self.script("hapus"), self.out.append))
        self.assertTrue(os.path.exists(self.reg()))
        self.assertTrue(firstrun.reset(self.data, self.dbo, self.script("HAPUS"), self.out.append))
        self.assertFalse(os.path.exists(self.reg()))

    def test_mysql_gagal_lalu_pengguna_bisa_keluar(self):
        d = db.Database(self.data)
        d.engine = "mysql"
        d.cfg = dict(db.DEFAULTS, port=1)
        ok = firstrun.step_mysql(self.data, d, self.script("3"), lambda p="": "", self.out.append)
        self.assertFalse(ok)
        self.assertTrue(any("GAGAL" in line for line in self.out))


if __name__ == "__main__":
    unittest.main(verbosity=2)
