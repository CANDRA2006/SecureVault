# Arsitektur SecureVault

Dokumen ini menjelaskan desain internal SecureVault: alur enkripsi/dekripsi, keputusan desain kriptografi, dan struktur modul.

---

## Gambaran Umum

```
┌─────────────────────────────────────────────┐
│                  cli.cpp                    │
│         (parsing argumen & I/O terminal)    │
└────────────────────┬────────────────────────┘
                     │
        ┌────────────▼────────────┐
        │     crypto_engine.cpp   │
        │  vault_encrypt()        │
        │  vault_decrypt()        │
        │  pbkdf2_derive()        │
        │  aes_gcm_encrypt/decrypt│
        └────────────┬────────────┘
                     │
        ┌────────────▼────────────┐
        │       file_io.cpp       │
        │  read_file()            │
        │  atomic_write_file()    │
        └─────────────────────────┘
```

---

## Alur Enkripsi

```
Password + Plaintext
        │
        ▼
1. Generate salt (32 byte, CSPRNG)
2. Generate nonce utama (12 byte, CSPRNG)
3. PBKDF2-HMAC-SHA256(password, salt, iterations) → main_key (32 byte)
        │
        ▼
4. [Jika ada metadata]
   meta_salt = HMAC-SHA256(salt, "SecureVault-Metadata-v1")
   PBKDF2(password, meta_salt, iterations) → meta_key
   Generate meta_nonce (12 byte, CSPRNG)
   AES-256-GCM(meta_key, meta_nonce, metadata) → enc_metadata_block
        │
        ▼
5. Susun header tetap (60 byte):
   magic | version | algorithm | flags | iterations | salt | nonce | metadata_len
        │
        ▼
6. AES-256-GCM(main_key, nonce, AAD=header, plaintext) → ciphertext+tag
        │
        ▼
7. Output: header || enc_metadata_block || ciphertext+tag
```

### Catatan Penting

- **AAD (Additional Authenticated Data)** mencakup seluruh 60 byte header tetap. Setiap perubahan pada field header mana pun akan menyebabkan verifikasi tag GCM gagal saat dekripsi.
- **Metadata dienkripsi terpisah** menggunakan kunci dan nonce yang berbeda. Ini memungkinkan deteksi manipulasi metadata secara terpisah dari deteksi manipulasi ciphertext utama.
- **Domain separation** pada kunci metadata menggunakan HMAC-SHA256, bukan sekadar XOR byte (seperti pada implementasi lama yang lemah).

---

## Alur Dekripsi

```
Ciphertext blob + Password
        │
        ▼
1. vault_parse_header() → validasi magic, version, algorithm, iterations
2. serialize_header() → rekonstruksi AAD (harus identik dengan saat enkripsi)
3. PBKDF2(password, salt, iterations) → main_key
        │
        ▼
4. AES-256-GCM decrypt(main_key, nonce, AAD=header, ciphertext+tag)
   → GAGAL → AUTHENTICATION_FAILED (password salah atau data rusak)
   → SUKSES → plaintext valid
        │
        ▼
5. [Jika metadata_len > 0]
   meta_salt = HMAC-SHA256(salt, "SecureVault-Metadata-v1")
   PBKDF2(password, meta_salt) → meta_key
   AES-256-GCM decrypt(meta_key, meta_nonce, enc_metadata)
   → GAGAL → result.metadata_corrupt = true (peringatan ke user)
   → SUKSES → result.metadata = deserialized Metadata
```

---

## Modul dan Tanggung Jawabnya

### `crypto_engine.cpp` / `crypto_engine.h`

Inti kriptografi. Mengekspos API publik:

| Fungsi | Keterangan |
|---|---|
| `vault_encrypt()` | Enkripsi plaintext → blob vault |
| `vault_decrypt()` | Dekripsi blob vault → plaintext + metadata |
| `vault_parse_header()` | Parse header tanpa dekripsi (untuk perintah `info`) |
| `pbkdf2_derive()` | Derivasi kunci via PBKDF2-HMAC-SHA256 |
| `csprng_fill()` | Isi buffer dengan byte acak kriptografis (OS RNG) |
| `serialize_header()` | Serialisasi header ke byte LE yang portabel |
| `ct_equal()` | Perbandingan constant-time (via `CRYPTO_memcmp`) |

### `cli.cpp`

Antarmuka pengguna. Tanggung jawab:
- Parsing argumen dan flags
- Membaca password dari terminal (echo off via `TerminalGuard` RAII)
- Memanggil `vault_encrypt` / `vault_decrypt`
- Menampilkan peringatan `metadata_corrupt` ke user
- RAII guard (`PlaintextGuard`, `PasswordGuard`) memastikan buffer sensitif di-zero

### `file_io.cpp`

Penulisan file yang aman:
- `read_file()`: membaca file dengan batas `MAX_FILE_SIZE` (1 GB)
- `atomic_write_file()`: menulis ke `.svtmp` → fsync → rename atomik

### `secure_mem.h`

Header-only. Berisi:
- `secure_zero()`: zeroization platform-agnostic (pakai `SecureZeroMemory` di Windows, volatile loop + memory barrier di POSIX)
- `PlaintextGuard`: RAII destructor yang meng-zero vector plaintext
- `PasswordGuard`: RAII destructor yang meng-zero string password

### `attack_simulation.cpp`

Estimasi ketahanan password terhadap brute-force GPU. Menggunakan benchmark hashcat RTX 4090 sebagai basis (bukan asumsi CPU naif).

### `benchmark.cpp`

Mengukur:
- Waktu KDF pada berbagai jumlah iterasi
- Throughput AES-256-GCM encrypt/decrypt (MB/s)
- Overhead metadata

### `src/asm/`

Assembly x86-64 untuk dua operasi kritis:

| File | Fungsi | Keterangan |
|---|---|---|
| `secure_wipe.asm` | `secure_wipe()` | Zeroization QWORD + SFENCE; mendukung POSIX & Windows ABI |
| `xor_core.asm` | `xor_core()` | XOR in-place QWORD-optimized; mendukung dual ABI |

---

## Format Biner Detail

```
Offset  Len  Field
──────  ───  ─────────────────────────────────────────────────────
0       4    Magic: 0x53 0x56 0x4C 0x54 ("SVLT")
4       1    Versi format (0x01)
5       1    Algoritma (0x01 = AES-256-GCM)
6       2    Flags (reserved, harus 0x0000)
8       4    Iterasi KDF (uint32_t LE)
12      32   Salt (CSPRNG)
44      12   Nonce utama (CSPRNG)
56      4    Panjang blok metadata (uint32_t LE)
60      N    Blok metadata terenkripsi:
              └─ [12 byte meta_nonce][ciphertext+16 byte tag]
60+N    M    Ciphertext utama
60+N+M  16   GCM authentication tag utama
```

Total ukuran minimum (tanpa metadata, plaintext kosong): `60 + 0 + 0 + 16 = 76 byte`

---

## Keputusan Desain

### Mengapa PBKDF2, bukan Argon2?

PBKDF2-HMAC-SHA256 dipilih karena tersedia di OpenSSL tanpa dependensi tambahan dan cukup memadai pada 600k iterasi. Argon2 (memory-hard) lebih direkomendasikan untuk sistem baru, namun memerlukan libargon2 tambahan.

### Mengapa metadata dienkripsi terpisah?

Agar manipulasi metadata dapat dideteksi dan dilaporkan secara terpisah dari kegagalan autentikasi ciphertext utama. Ini memungkinkan peringatan granular kepada user (field `metadata_corrupt`) tanpa menolak plaintext yang sesungguhnya valid.

### Mengapa serialisasi header menggunakan fungsi terpisah (`serialize_header`)?

Untuk menghilangkan duplikasi (DRY) antara path enkripsi dan dekripsi. Kedua path harus menghasilkan byte AAD yang identik — jika logika serialisasi berbeda, tag GCM akan selalu gagal. Satu fungsi bersama mengeliminasi risiko ini.