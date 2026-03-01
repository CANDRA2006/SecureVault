# Riwayat Perubahan (Changelog)

Semua perubahan signifikan pada SecureVault didokumentasikan di sini.

Format mengikuti [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [2.0.0] — Rilis Terkini

### Keamanan — Perbaikan Kritis

- **Domain separation metadata ditingkatkan**: kunci metadata kini diturunkan menggunakan `HMAC-SHA256(salt, "SecureVault-Metadata-v1")` sebagai salt terpisah, menggantikan implementasi lama yang hanya meng-XOR satu byte salt terakhir (kelemahan kriptografis serius)
- **Deteksi manipulasi metadata eksplisit**: kegagalan autentikasi blok metadata kini disimpan dalam field `DecryptResult::metadata_corrupt` dan ditampilkan sebagai peringatan kepada pengguna, alih-alih diabaikan secara diam-diam
- **Fix byte order timestamp**: deserialisasi timestamp metadata kini menggunakan little-endian yang konsisten; implementasi sebelumnya salah membacanya sebagai big-endian
- **Estimasi serangan GPU realistis**: `attack_simulation.cpp` kini menggunakan throughput PBKDF2 GPU yang sebenarnya (~1.667 tebakan/detik per RTX 4090 pada 600k iterasi), bukan asumsi naif 1 miliar tebakan/detik tanpa memperhitungkan cost KDF

### Keamanan — Perbaikan Desain

- **`serialize_header()` diekstrak (DRY)**: fungsi bersama tunggal digunakan oleh `vault_encrypt` dan `vault_decrypt` untuk menghasilkan byte AAD yang identik, mengeliminasi risiko ketidakkonsistenan
- **RAII memory guards**: `PlaintextGuard` dan `PasswordGuard` memastikan buffer sensitif di-zero pada setiap jalur keluar — normal, early return, maupun exception
- **Batas input ditegakkan**: `MAX_FILE_SIZE` (1 GB) dan `MAX_PASSWORD_LEN` (1024 byte) kini divalidasi sebelum operasi KDF yang mahal
- **`ct_equal()` via `CRYPTO_memcmp`**: perbandingan constant-time menggunakan fungsi OpenSSL yang telah diaudit

### Perbaikan Bug

- **`ct_size` di `cmd_info`**: sebelumnya menggunakan aritmetika unsigned yang dapat menghasilkan underflow jika ukuran blob tidak valid; kini menggunakan aritmetika signed dengan pemeriksaan eksplisit
- **`TerminalGuard` RAII**: terminal echo sekarang selalu dipulihkan meski terjadi exception saat membaca password
- **Validasi `metadata_len`**: pemeriksaan overflow integer saat parsing header mencegah akses memori di luar batas
- **`xor_core.asm` dual ABI**: implementasi lama hanya mendukung Windows x64 ABI; kini mendukung POSIX x86-64 (Linux/macOS) dan Windows x64

### Perubahan

- **Global state dieliminasi**: struct `Options` kini lokal per pemanggilan `cli_main`, bukan variabel global — mencegah state yang bocor antar pemanggilan dalam penggunaan library
- **Iterasi KDF default**: ditingkatkan ke 600.000 sesuai rekomendasi NIST 2023 (dari 100.000 pada v1)
- **Flag `metadata_corrupt` ditambahkan** ke `DecryptResult`
- **Perintah `rotate-key`**: metadata dari file asli kini dipertahankan dalam file hasil rotasi (kecuali metadata rusak/ter-tamper)

### Penambahan

- `benchmark_main.cpp` — entry point biner benchmark terpisah (sebelumnya hilang dari repo)
- **Test baru**: `metadata_tampering_detected`, `metadata_timestamp_byte_order`, `metadata_zero_timestamp`, `metadata_max_timestamp`, `encrypt_different_runs_produce_different_ct`
- **Self-test baru**: Test 6 — deteksi manipulasi metadata
- `src/asm/secure_wipe.asm` — implementasi assembly untuk `secure_wipe()` dengan SFENCE
- `src/asm/xor_core.asm` — XOR QWORD-optimized dengan dukungan dual ABI

---

## [1.0.0] — Versi Awal

### Fitur Awal

- Enkripsi file dengan AES-256-GCM via OpenSSL
- Derivasi kunci PBKDF2-HMAC-SHA256 (100k iterasi default)
- Format file biner berversi dengan magic bytes `SVLT`
- Penyematan metadata terenkripsi (nama file asli + timestamp)
- Antarmuka CLI: `enc`, `dec`, `info`, `self-test`
- Penulisan file atomik (temp-file + rename)
- Dukungan Linux, macOS, Windows

### Kelemahan yang Diketahui pada v1 (Diperbaiki di v2)

- Domain separation kunci metadata menggunakan XOR satu byte (lemah)
- Manipulasi metadata diabaikan secara diam-diam tanpa peringatan ke pengguna
- Byte order timestamp tidak konsisten (bug deserialisasi)
- Estimasi waktu serangan mengasumsikan 1 miliar tebakan/detik (tidak realistis)
- `ct_size` dalam `cmd_info` berpotensi unsigned underflow
- `xor_core.asm` hanya mendukung Windows ABI
- Tidak ada batas ukuran file atau panjang password
- Opsi global (bukan lokal), berpotensi state bocor