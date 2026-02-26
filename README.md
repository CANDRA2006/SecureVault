## IN THE PROCESS
# SECURE VAULT

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Language: C++17](https://img.shields.io/badge/Language-C%2B%2B17-brightgreen.svg)
![Crypto: AES-256-GCM](https://img.shields.io/badge/Crypto-AES--256--GCM-orange.svg)

**SecureVault** adalah aplikasi enkripsi file command-line berbasis **C++ + x86-64 Assembly** dengan kriptografi modern (AES-256-GCM), key derivation yang kuat (PBKDF2-HMAC-SHA256), dan format file berversi.

> v2.0 merupakan upgrade penuh dari versi pembelajaran ke implementasi production-grade.

---

## Fitur Utama

| Fitur | Status |
|---|---|
| AES-256-GCM (AEAD) | ✅ Real implementation via OpenSSL |
| PBKDF2-HMAC-SHA256 (KDF) | ✅ 600k iterations default (NIST 2023) |
| Format file berversi (SVLT) | ✅ magic + version + algo + salt + nonce + ciphertext + tag |
| Authenticated encryption | ✅ GCM tag melindungi header + ciphertext |
| Metadata terenkripsi | ✅ filename + timestamp, domain-separated key |
| Atomic file write | ✅ write → fsync → rename (crash-safe) |
| CSPRNG OS | ✅ via OpenSSL RAND_bytes |
| Secure zeroize | ✅ volatile write + compiler barrier |
| Constant-time compare | ✅ via CRYPTO_memcmp |
| Interactive password | ✅ tanpa echo terminal |
| Key rotation | ✅ `rotate-key` command |
| Self-test built-in | ✅ 5 KAT checks |
| Unit tests (36 cases) | ✅ semua pass |
| Benchmark | ✅ KDF + throughput + metadata overhead |

---

## Arsitektur Kriptografi

```
Password + Salt ──→ PBKDF2-HMAC-SHA256 (600k iter) ──→ 256-bit Key
                                                              │
Plaintext ───────────────────────────────────────────→ AES-256-GCM ──→ Ciphertext + 128-bit Tag
                                                              │
Header (AAD: magic+version+algo+iterations+salt+nonce) ──────┘
```

**Kenapa AES-256-GCM, bukan ChaCha20-Poly1305?**
- Hardware AES-NI tersedia di hampir semua x86-64 sejak 2011 → ~3-5× lebih cepat
- OpenSSL EVP API menyediakan wrapper yang well-audited
- ChaCha20 lebih unggul di platform mobile/embedded, bukan target utama project ini

**Kenapa PBKDF2, bukan Argon2id?**
- Argon2id tidak ada di OpenSSL mainline; membutuhkan libargon2 sebagai dependency tambahan
- PBKDF2-600k sudah memenuhi rekomendasi NIST SP 800-132 (2023)
- KDF type disimpan dalam header → future migration ke Argon2id trivial (version bump)

---

## Format File Binary (SVLT v1)

Lihat [`docs/file_format.md`](docs/file_format.md) untuk spesifikasi lengkap.

```
Offset  Size  Field
──────────────────────────────────────────────────
 0       4    Magic: 0x53 0x56 0x4C 0x54 ("SVLT")
 4       1    Version: 0x01
 5       1    Algorithm: 0x01 = AES-256-GCM
 6       2    Flags (reserved, 0x0000)
 8       4    KDF iterations (uint32_t LE)
12      32    Salt (CSPRNG)
44      12    Nonce/IV (CSPRNG)
56       4    Metadata block length (uint32_t LE)
60       N    Encrypted metadata block (if N > 0)
60+N    M    Ciphertext
60+N+M  16   GCM authentication tag
```

---

## Struktur Project

```
SecureVault/
│
├── include/
│   ├── crypto_engine.h        ← Interface AES-256-GCM, PBKDF2, SecureKey RAII, CryptoError
│   ├── vault_format.h         ← Definisi format biner SVLT: magic, FileHeader, Metadata
│   ├── file_io.h              ← Interface atomic write (write→fsync→rename)
│   ├── secure_mem.h           ← secure_zero() dengan volatile barrier + forward decl ASM
│   ├── aes.h                  ← [Legacy stub] backward compat, tidak aktif dipakai
│   └── pbkdf2.h               ← [Legacy stub] backward compat, delegate ke OpenSSL
│
├── src/
│   ├── asm/
│   │   ├── secure_wipe.asm    ← x86-64: QWORD wipe loop + sfence, dual ABI (POSIX/Windows)
│   │   └── xor_core.asm       ← x86-64: QWORD XOR loop, dual ABI (POSIX/Windows)
│   │
│   ├── crypto/
│   │   ├── crypto_engine.cpp  ← Implementasi utama: GCM encrypt/decrypt, PBKDF2, metadata
│   │   └── secure_memory.cpp  ← [Stub] placeholder CMake, logika ada di secure_mem.h
│   │
│   ├── cli.cpp                ← Semua commands (enc/dec/info/rotate-key/self-test) + flag parsing
│   ├── main.cpp               ← Entry point → cli_main()
│   ├── file_io.cpp            ← Atomic write: POSIX fdatasync+rename / Win32 FlushFileBuffers
│   ├── benchmark.cpp          ← Benchmark KDF + AES-256-GCM throughput + metadata overhead
│   ├── benchmark_main.cpp     ← Entry point binary benchmark terpisah
│   └── attack_simulation.cpp  ← Analisis entropi password + estimasi brute-force time
│
├── tests/
│   └── test_crypto.cpp        ← 36 unit tests: CSPRNG, KDF, roundtrip, tamper, fuzz truncation
│
├── docs/
│   ├── file_format.md         ← Spesifikasi biner format SVLT v1 (offset, ukuran, tipe tiap field)
│   └── security_considerations.md ← Threat model, trade-off desain, batasan, rekomendasi
│
├── build/                     ← Artefak build (di-ignore oleh .gitignore)
│   ├── securevault            ← Binary utama
│   ├── securevault_bench      ← Binary benchmark
│   └── test_crypto            ← Binary unit test
│
├── CMakeLists.txt             ← Build system: vault_crypto lib + 3 targets + CTest
└── README.md
```

---

## Build

### Prerequisites

- g++ ≥ 11 (C++17)
- OpenSSL development headers + libraries (`libssl-dev` pada Debian/Ubuntu)
- NASM (opsional, untuk ASM optimisasi)
- CMake ≥ 3.15

### Dengan CMake (recommended)

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

### Dengan g++ langsung

```bash
mkdir build

# Compile objects
g++ -std=c++17 -O2 -Iinclude -c src/crypto/crypto_engine.cpp -o build/crypto_engine.o
g++ -std=c++17 -O2 -Iinclude -c src/file_io.cpp              -o build/file_io.o
g++ -std=c++17 -O2 -Iinclude -c src/benchmark.cpp            -o build/benchmark.o
g++ -std=c++17 -O2 -Iinclude -c src/attack_simulation.cpp    -o build/attack_sim.o
g++ -std=c++17 -O2 -Iinclude -c src/cli.cpp                  -o build/cli.o
g++ -std=c++17 -O2 -Iinclude -c src/main.cpp                 -o build/main.o

# Link
g++ build/*.o -lssl -lcrypto -o build/securevault
```

---

## Cara Penggunaan

### Enkripsi file

```bash
./securevault enc secret.txt secret.vault
# Password diminta interaktif (tanpa echo)
```

### Dekripsi file

```bash
./securevault dec secret.vault secret.txt --force
```

### Lihat info file (tanpa dekripsi)

```bash
./securevault info secret.vault
```

Output:
```
=== SecureVault File Info ===
Format version : 1
Algorithm      : AES-256-GCM
KDF iterations : 600000
Salt           : 3b410afd...
Nonce          : 9b2fef2d...
Metadata block : 51 bytes (encrypted)
Ciphertext     : 64 bytes
```

### Rotasi kunci

```bash
./securevault rotate-key secret.vault secret_new.vault --iterations 1000000
```

### Self-test

```bash
./securevault self-test
```

### Flags tersedia

| Flag | Deskripsi |
|---|---|
| `--iterations N` | PBKDF2 iterations (default: 600000, min: 100000) |
| `--force` | Overwrite file output tanpa prompt |
| `--verbose` | Tampilkan timing dan metadata |
| `--no-metadata` | Jangan embed filename/timestamp |

### Exit codes

| Code | Arti |
|---|---|
| 0 | Sukses |
| 1 | Usage error / argument salah |
| 2 | I/O error |
| 3 | Crypto / authentication error |
| 4 | Internal error |

---

## Testing

```bash
# Build test binary
g++ -std=c++17 -Iinclude tests/test_crypto.cpp \
    build/crypto_engine.o build/file_io.o \
    -lssl -lcrypto -o build/test_crypto

# Jalankan
./build/test_crypto
```

Output:
```
=== SecureVault Unit Tests ===
[PASS] csprng returns success
[PASS] kdf success
... (36 tests total)
=== Results: 36 passed, 0 failed ===
```

Dengan CMake + CTest:
```bash
cd build && ctest --verbose
```

---

## Benchmark Results

```
=== KDF Benchmark (PBKDF2-HMAC-SHA256) ===
Iterations     Time (ms)
100000         25.4
300000         90.3
600000         152.9   ← default
1000000        264.5

=== AES-256-GCM Throughput ===
Size      Enc (MB/s)    Dec (MB/s)
1 KB          0.0           0.0    ← KDF dominates
64 KB         2.6           2.7
1 MB         39.1          29.8
10 MB        227.6         245.9   ← near hardware AES-NI speeds

=== Metadata Overhead ===
Without metadata: 23.52 ms, 4172 bytes
With metadata:    49.80 ms, 4240 bytes
Overhead: 68 bytes (1 extra KDF + 68 bytes header)
```

---

## Model Keamanan

Lihat [`docs/security_considerations.md`](docs/security_considerations.md) untuk detail.

**Dilindungi:**
- Konfidensialitas: AES-256-GCM ciphertext tidak dapat dibaca tanpa password + salt
- Integritas: GCM tag melindungi header + ciphertext — modifikasi apapun terdeteksi
- Password brute-force: PBKDF2-600k membuat setiap guess ~153ms
- Crash safety: atomic write strategy (write → fsync → rename)
- Memory: key material di-zeroize setelah digunakan

**Tidak dilindungi (di luar scope):**
- Side-channel via timing pada KDF (PBKDF2 tidak constant-time)
- Metadata confidentiality dari info command (salt/nonce visible)
- Keamanan di sistem operasi yang sudah terkompromi

---

## License

MIT License — Copyright (c) 2026 CANDRA

Bebas digunakan, dimodifikasi, dan didistribusikan untuk tujuan apapun selama
mencantumkan copyright notice ini. Lihat file [LICENSE](LICENSE) untuk teks lengkap.

---

## Author

CANDRA 
