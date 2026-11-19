-- Contoh query untuk melihat dan memanipulasi hasil enkripsi SilentReport di MySQL.
-- Buka dengan: mysql -u root -p silentreport   (atau MySQL Workbench / phpMyAdmin / HeidiSQL)
-- Semua kolom ciphertext berupa teks base64 (kecuali attachments.data yang berupa BLOB).

-- 1. Lihat isi mentah (terenkripsi)
SELECT id, username, role, LEFT(pw_hash, 60) AS pw_hash, LEFT(face_template, 40) AS face_ct FROM users;
SELECT id, report_id, important, LEFT(body, 80) AS ciphertext, LENGTH(body) AS panjang FROM messages;
SELECT id, kind, LENGTH(data) AS ukuran_byte, HEX(LEFT(data, 12)) AS nonce_hex, sha256 FROM attachments;
SELECT idx, LEFT(hash, 16) AS hash, nonce, prev_hash FROM blocks ORDER BY idx;

-- 2. Uji integritas: ubah SATU karakter ciphertext pesan -> halaman laporan menampilkan [DATA RUSAK]
--    karena tag autentikasi AES-GCM gagal (ganti 1 dengan id pesan yang ada).
UPDATE messages SET body = CONCAT(LEFT(body, 40), IF(SUBSTRING(body, 41, 1) = 'A', 'B', 'A'), SUBSTRING(body, 42)) WHERE id = 1;

-- 3. Uji perlindungan lapisan DB: lepas flag 'important' -> dekripsi gagal (tidak bisa diakali)
UPDATE messages SET important = 0 WHERE id = 1;

-- 4. Uji file terenkripsi: balik satu bit pada BLOB -> unduhan ditolak (autentikasi ChaCha20-Poly1305 gagal)
UPDATE attachments SET data = CONCAT(LEFT(data, 20), CHAR(ASCII(SUBSTRING(data, 21, 1)) ^ 255 USING latin1), SUBSTRING(data, 22)) WHERE id = 1;

-- 5. Uji blockchain: ubah isi blok -> halaman Rantai bukti menampilkan TIDAK VALID
UPDATE blocks SET data = REPLACE(data, 'BUKTI_DIUNDUH', 'TIDAK_ADA') WHERE idx = 1;

-- 6. Uji autentikasi wajah: kosongkan templat -> login ditolak (tidak bisa mendaftar ulang lewat DB)
UPDATE users SET face_template = NULL WHERE username = 'nama_samaran';

-- 7. Ukur kinerja massal: banyak baris untuk uji performa tampilan (contoh 1000 baris salinan pesan)
INSERT INTO messages (report_id, sender_id, body, important, created)
SELECT report_id, sender_id, body, important, UNIX_TIMESTAMP() FROM messages
JOIN (SELECT 1 AS n UNION SELECT 2 UNION SELECT 3 UNION SELECT 4 UNION SELECT 5) k WHERE messages.id = 1;
