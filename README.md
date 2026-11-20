# SilentReport: Aplikasi Pelaporan Anonim Berbasis Kriptografi

Chat aman antara **pelapor** (anonim, pakai nama samaran) dan **petugas** (mis. inspektorat kampus)
untuk melaporkan korupsi, perundungan, atau pelecehan. Dibuat untuk memenuhi 7 kriteria Tugas Akhir Kriptografi.

> **Pengguna biasa:** cukup klik dua kali `SilentReport.exe` / `SilentReport.bat`. Lihat `PANDUAN_PENGGUNA.md`.
> Butuh **server MySQL/MariaDB** yang menyala (mis. XAMPP, MySQL Installer, atau Docker). Bagian 2-4 di bawah hanya untuk pengembang.

## 0. Membuat SilentReport.exe (sekali, oleh pengembang, di Windows)

```
build_exe.bat      -> menghasilkan SilentReport.exe (satu file, tanpa perlu Python di komputer pengguna)
```
Bagikan `SilentReport.exe` saja. Data pengguna disimpan di `%APPDATA%\SilentReport`, bukan di folder program.
Linux/macOS: `./build_exe.sh` (hasil di `dist/`). Catatan: build `.exe` harus dijalankan di Windows.

## 1. Pemetaan kriteria dosen ke kode

| # | Kriteria dosen | Implementasi | File / fungsi |
|---|---|---|---|
| 1 | Login biometrik, aplikasi hanya hidup dengan dongle | Biometrik **wajah lewat kamera** (histogram LBP + jarak chi-square). Aplikasi **terkunci (HTTP 423)** tanpa dongle USB, juga bila dongle dicabut saat berjalan. Dongle dibuat pada peluncuran pertama dengan memilih dan mengonfirmasi flashdisk | `sr_crypto/face.py`, `sr_crypto/dongle.py`, `firstrun.py`, `app.py` (`guard`, `login`) |
| 2 | Login memakai algoritma kriptografi | Password di-hash **scrypt + salt acak** (n=2^14), dibandingkan dengan `hmac.compare_digest` | `sr_crypto/passwords.py` |
| 3 | Pesan teks: super enkripsi (klasik + modern) | **Extended Vigenere** (klasik) lalu **AES-256-GCM** (modern) | `sr_crypto/classic.py`, `sr_crypto/textcrypto.py` |
| 4 | Pesan file: kriptografi beda dari teks | **ChaCha20-Poly1305** dengan kunci sendiri | `sr_crypto/filecrypto.py` |
| 5 | Pesan penting dienkripsi di basisdata | Pesan bertanda "penting" dibungkus lagi **AES-256-GCM kunci DB** (terpisah dari kunci teks) | `sr_crypto/dbcrypto.py`, `app.py` (`store_message`) |
| 6 | Pesan gambar: steganografi | **LSB** pada kanal R,G,B; catatan rahasia dienkripsi lalu disisipkan ke foto bukti, disimpan PNG | `sr_crypto/stego.py` |
| 7 | Aset penting: blockchain sederhana | Rantai blok SHA-256 + Proof-of-Work (3 nol) untuk **chain of custody barang bukti** | `sr_crypto/blockchain.py`, `app.py` (`add_block`) |

**Manajemen kunci:** satu master secret 32 byte ada di dongle USB. Semua kunci diturunkan dengan **HKDF-SHA256**
dengan label berbeda (`text-vigenere`, `text-aes256`, `file-chacha20`, `db-aes256`). Tanpa dongle, isi MySQL (termasuk file bukti)
tidak bisa didekripsi.

## 2. Instalasi

Butuh Python 3.10+ dan server MySQL 5.7+/8.x atau MariaDB 10.4+ (XAMPP: tekan Start pada MySQL).

```bash
python -m venv venv
# Windows:  venv\Scripts\activate        Linux/Mac:  source venv/bin/activate
pip install -r requirements.txt          # termasuk PyMySQL
python tools/check_mysql.py              # cek mandiri sambungan MySQL (membuat lalu menghapus database sementara)
```

## 3. Peluncuran pertama (jendela hitam SilentReport.bat): MySQL dan dongle

Klik dua kali `SilentReport.bat`. Pada jendela konsol, wizard berjalan:

1. **Sambungan MySQL.** Bawaan `root@127.0.0.1:3306`, database `silentreport` (dibuat otomatis bila belum ada). Bila gagal
   (MySQL belum menyala, password salah) wizard menampilkan sebabnya dan menawarkan ubah pengaturan, coba lagi, atau keluar.
   Pengaturan tersimpan di `mysql.json` pada folder data (`%APPDATA%\SilentReport`).
2. **Pilih flashdisk dongle.** Wizard menampilkan daftar drive dengan nomor, nama volume, dan kapasitas. Anda mengetik nomor,
   melihat ringkasan pilihan, lalu harus mengetik **YA** (huruf besar) sebelum kunci `.silentreport.key` ditulis ke drive itu.
   Drive lain tidak disentuh. Bila drive sudah berisi kunci SilentReport, wizard memberi peringatan penimpaan.
   Bila database sudah berisi akun tetapi dongle tidak terdaftar, wizard **menolak** membuat kunci baru (data lama akan yatim).
3. Kode undangan petugas ditampilkan di konsol, lalu aplikasi terbuka.

Peluncuran berikutnya hanya memeriksa MySQL (beberapa detik); dongle tidak dibuat ulang. Untuk **mulai dari nol saat pengujian**:
`python launcher.py --reset` (mengetik `HAPUS`; menghapus database, registri dongle, kode petugas).

Variabel lingkungan yang menimpa `mysql.json`: `SR_DB_HOST`, `SR_DB_PORT`, `SR_DB_USER`, `SR_DB_PASSWORD`, `SR_DB_NAME`.
Wizard web `/setup` tetap ada sebagai cadangan bila aplikasi dijalankan lewat `python app.py`.

## 4. Menjalankan mode pengembang

```bash
# Windows PowerShell:  $env:SR_DONGLE_PATH="E:\"      (tidak perlu jika flashdisk terdeteksi otomatis)
# Linux/Mac:           export SR_DONGLE_PATH=./fake_usb
python app.py
```

Buka http://127.0.0.1:5000. Tanpa dongle, aplikasi tetap menyala tetapi **seluruh halaman terkunci** (HTTP 423) dan terbuka
otomatis saat dongle terpasang. Bila MySQL mati, halaman "Database tidak tersedia" tampil (bukan galat mentah).

## 5. Skenario demo untuk presentasi (urut)

1. **Dongle:** buka aplikasi tanpa dongle (layar **Aplikasi terkunci**). Colok dongle: aplikasi terbuka otomatis. Cabut lagi: terkunci kembali.
2. **Registrasi pelapor:** nama samaran `pelapor1`, password, lalu foto wajah lewat kamera.
3. **Login:** wajah sama **berhasil**; wajah orang lain **ditolak**; password salah **ditolak**.
4. **Buat laporan:** isi teks, centang "penting", lampirkan satu file (PDF/dokumen) dan satu foto beserta catatan rahasia.
5. **Registrasi petugas** (jendela incognito), peran Petugas, masukkan kode undangan, lalu login sebagai petugas.
6. **Lihat hasil enkripsi langsung di MySQL** (Workbench/phpMyAdmin/`mysql`): buka tabel `messages`, `reports`, `attachments`, `users`.
   Semua isinya ciphertext base64 (file bukti berupa BLOB). Menu **Inspeksi kripto** menampilkan hal yang sama di aplikasi.
7. **Manipulasi untuk uji kriptografi** (contoh lengkap di `tools/contoh_query_mysql.sql`):
   - ubah satu karakter `messages.body`: halaman laporan menampilkan **[DATA RUSAK]** (tag AES-GCM gagal),
   - ubah `messages.important` menjadi 0: tetap gagal (lapisan DB tidak bisa diakali),
   - balik satu byte `attachments.data`: unduhan ditolak (tag ChaCha20-Poly1305 gagal),
   - ubah satu blok `blocks.data`: **Rantai bukti** berubah **TIDAK VALID**,
   - kosongkan `users.face_template`: login ditolak (wajah tidak bisa didaftarkan ulang lewat DB).
8. **Steganografi:** buka laporan, klik **Ekstrak pesan tersembunyi** pada foto. Bandingkan foto asli dan hasil stego (tampak sama).
9. **Kinerja:** `python tools/benchmark_crypto.py` mencetak waktu enkripsi/dekripsi teks, file 100 KB dan 5 MB, lapisan DB, serta penambangan blok.

## 5b. Fitur antarmuka

- Tema terang/gelap (tombol di header, pilihan diingat), responsif untuk HP dan laptop.
- Form: validasi langsung, tampilkan/sembunyikan password, indikator kekuatan password, penghitung karakter, tombol berstatus loading.
- Unggah file: seret-lepas, pratinjau gambar, pembatasan ukuran.
- Detail laporan: gelembung percakapan, progres status, kirim dengan Ctrl+Enter, perbesar foto bukti, salin hash.
- Daftar laporan: statistik ringkas, pencarian dan filter status.
- Rantai bukti: tampilan timeline dengan penanda blok yang rusak.
- Layar "Aplikasi terkunci" saat dongle dicabut. Semua fitur tetap berfungsi dasar bila JavaScript mati.

## 5c. Biometrik wajah (kamera)

Login memakai **dua faktor pengguna**: password dan wajah, ditambah dongle sebagai syarat aplikasi bisa dipakai sama sekali.
Biometrik sidik jari sudah dihapus dari aplikasi.

**Alur:** browser meminta izin kamera (`getUserMedia`, hanya jalan di `127.0.0.1`/localhost atau HTTPS) lalu mengambil
5-6 foto otomatis. Server mendeteksi wajah (LBP cascade), memotong dan menormalkan cahaya, lalu menghitung histogram
LBP seragam per sel (grid 6x6 x 59 bin) sebagai **tanda tangan wajah**. Yang disimpan di database hanya tanda tangan itu,
**dienkripsi AES-256-GCM dengan kunci DB** (dari dongle). **Foto tidak disimpan.** Saat login, jarak chi-square ke template
dihitung; lolos bila median jarak <= ambang (bawaan 0,18).

**Kontrol kualitas:** menolak gambar tanpa wajah, lebih dari satu wajah, terlalu gelap/terang, atau buram, dengan pesan yang jelas.
Saat pendaftaran, foto yang menyimpang dari foto "tengah" dibuang dan pendaftaran ditolak bila kurang dari 70% foto konsisten
(mencegah dua orang tercampur dalam satu template). Pesan kualitas tidak bergantung pada akun, jadi tidak membocorkan apakah
nama pengguna ada. Akun dengan template wajah kosong/rusak (mis. diubah lewat MySQL) **ditolak**, bukan didaftarkan ulang, agar penyerang yang bisa menulis ke database tidak dapat memasang wajahnya sendiri.

**Kalibrasi ambang dengan wajah asli (sangat disarankan sebelum demo):**
```bash
# foto_uji/budi/*.jpg  foto_uji/sari/*.jpg  ... (min. 2 orang, 8+ foto/orang, cahaya dan waktu berbeda)
python tools/calibrate_face.py foto_uji
# lalu pasang ambang yang disarankan, mis.:  $env:SR_FACE_THRESHOLD="0.182"   (Linux/Mac: export ...)
```

**Hasil uji yang sudah saya jalankan (jujur apa adanya):** hanya ada **dua wajah nyata** di lingkungan pengembangan
(foto astronot dan Grace Hopper) dan variasinya disimulasikan dari satu foto per orang (geser, rotasi, skala, cahaya, noise,
kompresi JPEG; `tools/face_sim.py`). Pada simulasi itu orang yang sama berjarak maks 0,14 dan orang berbeda min 0,22, tanpa salah
terima atau salah tolak pada 480 sesi uji. **Angka ini bukan akurasi sebenarnya**: variasi antar-sesi nyata (hari berbeda,
ekspresi, kacamata) lebih besar, dan dengan banyak orang akan ada pasangan wajah yang mirip. Alur kamera diuji di Chromium dengan
kamera virtual (registrasi, login wajah sama berhasil, wajah orang lain ditolak, izin kamera ditolak, unggah foto cadangan).

## 6. Pengujian otomatis

```bash
python -m unittest tests.test_criteria -v
```

76 tes memverifikasi: dongle dicabut, hash scrypt + salt, login wajah (sama lolos, orang lain ditolak, template diubah ditolak),
dua lapis enkripsi teks (dibuka manual per lapis), file ChaCha20 beda dari AES, lapisan DB pada pesan penting, steganografi
(maks. perubahan piksel = 1), blockchain valid dan pemalsuan terdeteksi, **manipulasi langsung di MySQL** (ciphertext/BLOB/blok diubah,
halaman tetap tidak crash dan perubahan terdeteksi), halaman galat saat MySQL mati, wizard konsol (pilih drive, konfirmasi YA,
penolakan data yatim, reset), serta CSRF dan kontrol akses.

Tes memakai database baru `srtest_<acak>` per tes pada MySQL yang berjalan (dihapus otomatis); atur koneksi lewat `SR_DB_*`.
Tanpa server MySQL: `SR_DB_ENGINE=sqlite python -m unittest tests.test_criteria -v` (mesin uji dengan skema dan kueri yang sama).
Pengguna dengan MySQL sebaiknya menjalankan kedua cara untuk memastikan driver dan skema MySQL bekerja di komputernya.

## 7. Struktur project

```
silentreport/
  launcher.py            peluncur pengguna akhir (port, jendela, folder data)
  SilentReport.bat/.sh/.command   klik dua kali untuk membuka
  build_exe.bat/.sh      membuat program mandiri dengan PyInstaller
  PANDUAN_PENGGUNA.md    panduan untuk pengguna awam
  app.py                 aplikasi Flask (rute, alur, kontrol akses)
  db.py                  lapisan MySQL (PyMySQL): skema, koneksi, konfigurasi
  firstrun.py            wizard konsol: sambungan MySQL, pilih dan konfirmasi flashdisk dongle
  make_dongle.py         pembuat dongle
  sr_crypto/             semua modul kriptografi dan wajah (satu file per kriteria)
  models/                detektor wajah (LBP cascade, lisensi BSD)
  static/js/camera.js    pengambilan foto wajah lewat kamera
  tools/calibrate_face.py  kalibrasi ambang wajah dengan foto asli
  tools/face_sim.py      simulator webcam untuk pengujian
  templates/             tampilan HTML (Jinja2)
  static/css/app.css     gaya antarmuka (tema terang/gelap, responsif)
  static/js/app.js       interaksi sisi klien (tanpa library)
  icons.py               ikon SVG garis (tanpa emoji)
  tools/check_mysql.py   cek mandiri sambungan MySQL
  tools/benchmark_crypto.py   ukur kinerja kriptografi
  tools/contoh_query_mysql.sql   contoh melihat dan memanipulasi ciphertext di MySQL
  tests/test_criteria.py          tes 7 kriteria
  data/ (atau %APPDATA%\SilentReport)   dongle.sha256, officer_code.txt, mysql.json (data aplikasi ada di MySQL)
```
