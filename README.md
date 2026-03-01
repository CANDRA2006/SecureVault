# SecureVault

**SecureVault** adalah alat enkripsi file berbasis command-line yang dibangun di atas AES-256-GCM dengan key derivation PBKDF2-HMAC-SHA256. Menyediakan enkripsi terautentikasi, penulisan file atomik, dan penyematan metadata opsional — dirancang untuk keamanan yang kuat dan dapat diaudit di Linux, macOS, dan Windows.

---

## Fitur Utama

- **AES-256-GCM** — enkripsi terautentikasi; mendeteksi setiap manipulasi pada ciphertext maupun header
- **PBKDF2-HMAC-SHA256** — jumlah iterasi KDF yang dapat dikonfigurasi (default: 600.000 sesuai rekomendasi NIST 2023)
- **Enkripsi metadata terpisah** — nama file asli dan timestamp disimpan dalam bentuk terenkripsi menggunakan kunci ber-domain-separation
- **Penulisan file atomik** — menggunakan temp-file + fsync + rename; tidak ada penulisan parsial saat terjadi crash
- **Keamanan memori RAII** — buffer sensitif di-zero pada setiap jalur keluar (normal, early return, maupun exception)
- **Secure wipe berbasis ASM** — `secure_wipe.asm` untuk zeroization memori, `xor_core.asm` untuk operasi XOR
- **Suite pengujian lengkap** — 43 unit test mencakup crypto, deteksi manipulasi, edge case, dan truncation fuzzing
- **Lintas platform** — Linux, macOS, Windows (x86-64)

---

## Mulai Cepat

```bash
# Build
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# Enkripsi file
./securevault enc rahasia.pdf rahasia.pdf.vault

# Dekripsi file
./securevault dec rahasia.pdf.vault rahasia.pdf

# Lihat metadata file (tanpa password)
./securevault info rahasia.pdf.vault

# Ganti kunci enkripsi
./securevault rotate-key lama.vault baru.vault

# Jalankan self-test
./securevault self-test
```

---

## Format File

SecureVault menggunakan format biner berversi dengan magic bytes `SVLT`. Semua integer disimpan dalam little-endian.

```
[0..3]   Magic: 0x53 0x56 0x4C 0x54  ("SVLT")
[4]      Versi format: 0x01
[5]      Algoritma: 0x01 = AES-256-GCM
[6..7]   Flags (dicadangkan, 0x0000)
[8..11]  Jumlah iterasi KDF (uint32_t LE)
[12..43] Salt (32 byte, CSPRNG)
[44..55] Nonce/IV (12 byte, CSPRNG)
[56..59] Panjang blok metadata (uint32_t LE, 0 = tidak ada)
[60..]   Blok metadata terenkripsi (jika ada)
         └─ 12-byte nonce || ciphertext+tag
[..]     Ciphertext
[16 byte terakhir] GCM authentication tag
```

GCM AAD mencakup seluruh header tetap (byte 0–59), sehingga setiap manipulasi pada field header mana pun — termasuk panjang metadata — akan terdeteksi dan ditolak.

---

## Referensi CLI

```
securevault enc <input> <output> [flags]
securevault dec <input> <output> [flags]
securevault info <file>
securevault rotate-key <input> <output> [flags]
securevault self-test
```

### Flags

| Flag | Default | Keterangan |
|---|---|---|
| `--iterations N` | 600000 | Jumlah iterasi PBKDF2 (min: 100.000) |
| `--force` | off | Timpa output tanpa konfirmasi |
| `--verbose` | off | Tampilkan waktu proses, ukuran file, dan metadata |
| `--no-metadata` | off | Lewati penyematan nama file/timestamp |

### Kode Keluar (Exit Codes)

| Kode | Arti |
|---|---|
| 0 | Sukses |
| 1 | Kesalahan penggunaan |
| 2 | Kesalahan I/O |
| 3 | Kesalahan kriptografi / autentikasi gagal |
| 4 | Kesalahan internal |

---

## Membangun (Build)

Lihat [`BUILD.md`](BUILD.md) untuk instruksi lengkap.

### Prasyarat

| Platform | Paket yang dibutuhkan |
|---|---|
| Ubuntu/Debian | `g++ libssl-dev nasm cmake` |
| macOS | `brew install openssl nasm cmake` |
| Windows | Visual Studio Build Tools + OpenSSL + NASM |

### CMake (direkomendasikan)

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
./build/test_crypto           # jalankan 43 unit test
./build/securevault self-test
```

### macOS (Homebrew OpenSSL)

```bash
cmake .. -DCMAKE_BUILD_TYPE=Release \
         -DOPENSSL_ROOT_DIR=$(brew --prefix openssl)
```

Output yang diharapkan:
```
=== Results: 43 tests, 43 passed, 0 failed ===
Self-test PASSED
```

---

## Catatan Keamanan

### Kekuatan Password

SecureVault menyertakan simulasi serangan bawaan yang memodelkan brute-force berbasis GPU menggunakan benchmark throughput PBKDF2 yang realistis:

- Satu RTX 4090: ~1.667 tebakan/detik pada 600k iterasi
- Pada 80+ bit entropy: secara praktis tidak bisa ditembus meski dengan kluster 1.000 GPU

**Rekomendasi:**
- Gunakan minimal 12 karakter acak dari charset ASCII printable penuh (≥78 bit entropy)
- Pada iterasi default 600k, password 12 karakter membutuhkan waktu bertahun-tahun untuk di-crack dengan satu GPU

### Jumlah Iterasi KDF

| Iterasi | Waktu perkiraan di CPU modern | Level keamanan |
|---|---|---|
| 100.000 | ~100ms | Minimum (data tidak sensitif) |
| 600.000 | ~600ms | Default — rekomendasi NIST 2023 |
| 1.000.000 | ~1 detik | Data sangat sensitif |

### Model Ancaman

SecureVault melindungi **data saat tidak aktif (at rest)** dari penyerang yang mendapatkan file terenkripsi namun tidak mengetahui password. SecureVault **tidak** melindungi dari:

- Malware di mesin yang melakukan enkripsi (keylogger, pembacaan memori)
- Serangan side-channel di level hardware
- Rekayasa sosial atau pemaksaan

---

## Struktur Proyek

```
securevault/
├── src/
│   ├── crypto/
│   │   └── crypto_engine.cpp    # Inti AES-256-GCM + PBKDF2
│   ├── asm/
│   │   ├── secure_wipe.asm      # Zeroization memori kriptografis
│   │   └── xor_core.asm         # XOR QWORD-optimized (dual ABI)
│   ├── main.cpp                 # Entry point utama
│   ├── cli.cpp                  # Antarmuka command-line
│   ├── file_io.cpp              # Penulisan file atomik
│   ├── benchmark.cpp            # Benchmark AES-GCM & KDF
│   ├── benchmark_main.cpp       # Entry point benchmark
│   └── attack_simulation.cpp    # Estimasi waktu crack password
├── include/
│   ├── crypto_engine.h          # API kriptografi publik
│   ├── vault_format.h           # Definisi format file & konstanta
│   ├── file_io.h                # API I/O file
│   ├── secure_mem.h             # Zeroization memori & RAII guard
│   ├── aes.h                    # Stub kompatibilitas (legacy)
│   └── pbkdf2.h                 # Stub kompatibilitas (legacy)
├── tests/
│   └── test_crypto.cpp          # 43 unit test
├── docs/
│   ├── ARCHITECTURE.md          # Penjelasan desain internal
│   ├── SECURITY.md              # Kebijakan keamanan & pelaporan
│   └── CHANGELOG.md             # Riwayat perubahan versi
├── CMakeLists.txt
├── BUILD.md
├── LICENSE
└── README.md
```

---

## Menjalankan Benchmark

```bash
./build/securevault_bench
```

Contoh output:

```
=== KDF Benchmark (PBKDF2-HMAC-SHA256) ===
Iterations     Time (ms)
------------------------------
100000         98.3
300000         294.1
600000         589.7
1000000        983.2

=== AES-256-GCM Throughput ===
Size           Enc (MB/s)          Dec (MB/s)
-------------------------------------------------------
1 KB           1823.4              1891.2
64 KB          2341.7              2398.5
1 MB           2489.3              2512.8
10 MB          2501.1              2528.4
```

---

## Lisensi

Proyek ini dilisensikan di bawah **MIT License**. Lihat file [`LICENSE`](LICENSE) untuk detail lengkap.

---

## Kontribusi

Kontribusi sangat disambut. Sebelum membuka pull request:

1. Pastikan semua 43 unit test lulus: `./build/test_crypto`
2. Jalankan self-test: `./build/securevault self-test`
3. Untuk pelaporan kerentanan keamanan, lihat [`docs/SECURITY.md`](docs/SECURITY.md)

## AUTHOR
CANDRA