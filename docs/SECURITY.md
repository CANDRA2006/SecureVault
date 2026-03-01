# Kebijakan Keamanan SecureVault

## Versi yang Didukung

| Versi | Status dukungan keamanan |
|---|---|
| 2.x (terkini) | ✅ Didukung penuh |
| 1.x | ❌ Tidak didukung — harap migrasi ke v2 |

---

## Melaporkan Kerentanan

Jika Anda menemukan kerentanan keamanan pada SecureVault, **jangan membuka GitHub issue publik**. Lakukan pelaporan secara bertanggung jawab melalui:

1. **Email**: kirim laporan ke alamat maintainer proyek dengan subjek `[SECURITY] SecureVault - <deskripsi singkat>`
2. **Informasi yang disertakan**:
   - Deskripsi kerentanan dan dampak yang mungkin terjadi
   - Langkah-langkah untuk mereproduksi masalah
   - Versi SecureVault yang terpengaruh
   - Proof of concept (jika ada) — boleh dalam bentuk pseudocode

Kami berkomitmen untuk merespons laporan dalam **72 jam** dan memberikan pembaruan status setiap 7 hari.

---

## Properti Keamanan

### Yang Dijamin

| Properti | Mekanisme |
|---|---|
| Kerahasiaan data | AES-256-GCM (kunci 256-bit) |
| Integritas ciphertext | GCM authentication tag (128-bit) |
| Integritas header | AAD mencakup seluruh 60 byte header tetap |
| Deteksi manipulasi metadata | Enkripsi + tag GCM terpisah per blok metadata |
| Perlindungan salt/nonce | Dicakup oleh AAD; perubahan → tag gagal |
| Penguatan password | PBKDF2-HMAC-SHA256, min. 100.000 iterasi |
| Domain separation kunci metadata | HMAC-SHA256(salt, label) sebagai salt turunan |
| Pembersihan memori | RAII guard + volatile loop + SFENCE |
| Penulisan file atomik | Temp-file + fsync + rename |

### Yang Tidak Dijamin

- **Keamanan endpoint**: SecureVault tidak melindungi dari malware di mesin lokal yang dapat membaca memori proses atau mencegat input keyboard.
- **Keamanan jaringan**: SecureVault adalah alat enkripsi file, bukan protokol komunikasi.
- **Penyembunyian ukuran file**: Ukuran plaintext dapat diperkirakan dari ukuran file vault (ukuran ciphertext ≈ ukuran plaintext + overhead tetap).
- **Keamanan metadata waktu**: Timestamp yang disematkan dalam metadata berasal dari jam sistem, yang dapat dimanipulasi oleh penyerang lokal dengan hak akses memadai.

---

## Analisis Kekuatan Kriptografi

### AES-256-GCM

- Kunci 256-bit memberikan keamanan 256-bit terhadap serangan brute-force kunci
- Tag GCM 128-bit memberikan probabilitas pemalsuan sebesar 2⁻¹²⁸ per percobaan
- Nonce 96-bit di-generate secara acak via CSPRNG OS untuk setiap operasi enkripsi

### PBKDF2-HMAC-SHA256

Throughput serangan GPU (benchmark hashcat RTX 4090, 2024):

| Iterasi | Tebakan/detik (1 GPU) | Tebakan/detik (1000 GPU) |
|---|---|---|
| 100.000 | ~10.000 | ~10.000.000 |
| 600.000 | ~1.667 | ~1.667.000 |
| 1.000.000 | ~1.000 | ~1.000.000 |

Waktu rata-rata crack password 8 karakter (charset 94, ~52 bit entropy) pada 600k iterasi dengan 1000 GPU: **~6 tahun**. Password 12 karakter (≥78 bit): **>1 juta tahun**.

### Pertimbangan Nonce

Dengan nonce 96-bit acak, probabilitas tabrakan nonce pada 2³² operasi enkripsi (4 miliar file) adalah ~2⁻³², masih dalam batas aman. Untuk penggunaan volume sangat tinggi, rekomendasikan rotasi kunci periodik.

---

## Mitigasi yang Diterapkan

### Terhadap Serangan Timing

- Perbandingan tag GCM dilakukan via `CRYPTO_memcmp` (constant-time) dari OpenSSL
- `ct_equal()` menggunakan `CRYPTO_memcmp` secara eksplisit

### Terhadap Kebocoran Memori

- `PlaintextGuard` dan `PasswordGuard` meng-zero buffer pada setiap jalur keluar
- `SecureKey` (RAII) meng-zero kunci kriptografi di destructor
- `secure_zero()` menggunakan `SecureZeroMemory` (Windows) atau volatile loop + memory barrier (POSIX) untuk mencegah optimasi compiler

### Terhadap Manipulasi File

- Header sepenuhnya dicakup oleh AAD GCM
- Metadata dienkripsi dan diautentikasi secara terpisah
- Truncation dan padding terdeteksi via validasi ukuran header

### Terhadap Input Berbahaya

- Batas ukuran file: `MAX_FILE_SIZE = 1 GB`
- Batas panjang password: `MAX_PASSWORD_LEN = 1024 byte`
- Validasi `metadata_len` untuk mencegah integer overflow
- Validasi range iterasi KDF (100k – 10jt)

---

## Dependensi Kriptografi

| Komponen | Library | Versi minimum |
|---|---|---|
| AES-256-GCM | OpenSSL EVP | 1.1.0+ |
| PBKDF2-HMAC-SHA256 | OpenSSL | 1.1.0+ |
| CSPRNG | OpenSSL `RAND_bytes` | 1.1.0+ |
| Constant-time compare | OpenSSL `CRYPTO_memcmp` | 1.1.0+ |
| HMAC-SHA256 (domain sep.) | OpenSSL `HMAC` | 1.1.0+ |

Kami mengikuti advisory keamanan OpenSSL. Pengguna disarankan selalu menggunakan versi OpenSSL terbaru yang didukung.

---

## Riwayat Perubahan Terkait Keamanan

Lihat [`CHANGELOG.md`](CHANGELOG.md) untuk riwayat perubahan lengkap. Perubahan signifikan terkait keamanan antara v1 dan v2:

- **Domain separation metadata**: dari XOR byte tunggal (lemah) ke HMAC-SHA256 penuh
- **Deteksi manipulasi metadata**: kini eksplisit via field `metadata_corrupt` alih-alih diabaikan diam-diam
- **Serialisasi header DRY**: satu fungsi `serialize_header()` bersama mencegah ketidakkonsistenan AAD antara enkripsi dan dekripsi
- **Byte order timestamp**: fix dari big-endian ke little-endian yang konsisten
- **Estimasi serangan GPU**: memperhitungkan cost PBKDF2 sebenarnya (sebelumnya mengasumsikan 1 miliar tebakan/detik tanpa iterasi KDF)
- **RAII memory guards**: memastikan zeroization pada semua jalur keluar
- **Batas input**: penegakan `MAX_FILE_SIZE` dan `MAX_PASSWORD_LEN`