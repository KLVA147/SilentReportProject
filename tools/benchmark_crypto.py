"""Ukur kinerja kriptografi SilentReport (tanpa server, tanpa MySQL).

    python tools/benchmark_crypto.py

Mengukur teks (Vigenere + AES-256-GCM), file (ChaCha20-Poly1305), lapisan DB (AES-GCM),
dan penambangan blok (PoW kesulitan 3), lalu mencetak tabel waktu rata-rata.
"""
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sr_crypto import blockchain, dbcrypto, filecrypto, textcrypto  # noqa: E402


def bench(fn, n):
    ts = []
    for _ in range(n):
        t = time.perf_counter()
        fn()
        ts.append((time.perf_counter() - t) * 1000)
    return statistics.mean(ts), min(ts), max(ts)


def main():
    master = os.urandom(32)
    text = "Pak X menerima suap di ruang rapat. " * 10
    tok = textcrypto.encrypt_text(text, master)
    rows = [
        ("Teks 360 B  enkripsi (Vigenere+AES-GCM)", bench(lambda: textcrypto.encrypt_text(text, master), 200)),
        ("Teks 360 B  dekripsi", bench(lambda: textcrypto.decrypt_text(tok, master), 200)),
        ("Field DB    enkripsi (AES-GCM)", bench(lambda: dbcrypto.encrypt_field(tok, master), 200)),
    ]
    for size, n in ((100 * 1024, 50), (5 * 1024 * 1024, 5)):
        data = os.urandom(size)
        enc = filecrypto.encrypt_bytes(data, master)
        rows.append(("File {:>5} KB enkripsi (ChaCha20-Poly1305)".format(size // 1024), bench(lambda: filecrypto.encrypt_bytes(data, master), n)))
        rows.append(("File {:>5} KB dekripsi".format(size // 1024), bench(lambda: filecrypto.decrypt_bytes(enc, master), n)))
    rows.append(("Blok blockchain (PoW 3 digit hex)", bench(lambda: blockchain.mine_block(1, {"a": 1}, "0" * 64), 10)))
    print("{:<48}{:>10}{:>10}{:>10}".format("Operasi", "rata ms", "min ms", "maks ms"))
    for name, (avg, lo, hi) in rows:
        print("{:<48}{:>10.3f}{:>10.3f}{:>10.3f}".format(name, avg, lo, hi))


if __name__ == "__main__":
    main()
