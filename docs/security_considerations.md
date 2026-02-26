# Security Considerations — SecureVault v2.0

## Model Ancaman (Threat Model)

### Aktor Ancaman

| Aktor | Kapabilitas | Di-scope? |
|-------|-------------|-----------|
| Attacker tanpa file | Tidak punya ciphertext | — |
| Attacker punya file | Punya ciphertext, tidak tahu password | ✅ utama |
| Attacker punya file + hash password | Brute-force offline | ✅ |
| Attacker di jaringan | MitM transfer file | Partial (tidak ada transport layer) |
| Attacker punya akses OS | Keylogger, memory dump | ❌ di luar scope |

---

## Properti Keamanan yang Dijamin

### 1. Konfidensialitas (Confidentiality)

AES-256-GCM dengan kunci 256-bit. Kunci diderivasi dari password via PBKDF2-HMAC-SHA256 dengan salt acak 256-bit dan ≥100.000 iterasi.

**Analisis kekuatan:**
- Dengan password 12 karakter (charset 94): ~78 bit entropy
- Dengan PBKDF2-600k: setiap attempt membutuhkan ~153ms pada CPU modern
- 10^6 attempts/hari → ~10^9 tahun untuk password 12 karakter penuh

### 2. Integritas dan Autentisitas (Integrity)

GCM authentication tag (128-bit) melindungi:
- Seluruh ciphertext
- Seluruh header (sebagai AAD): magic, version, algorithm, iterations, salt, nonce, metadata_len

Modifikasi apapun — bahkan 1 bit — terdeteksi dengan probabilitas error 2^-128 ≈ 0.

### 3. Salt Uniqueness

Salt 256-bit di-generate via OS CSPRNG (`RAND_bytes`). Probabilitas salt collision untuk 2^64 file: 2^(64-256) = 2^-192, negligible.

### 4. Nonce Uniqueness

Nonce GCM 96-bit juga di-generate via CSPRNG per file. Tidak ada counter-based nonce yang bisa overflow.

### 5. Memory Safety

- Key material dan password di-zeroize via `secure_zero()` (volatile write + asm memory barrier)
- `SecureKey` RAII: destructor otomatis memanggil zeroize
- Plaintext di-zeroize setelah digunakan di path dekripsi

---

## Trade-off dan Keputusan Desain

### PBKDF2 vs Argon2id

| Aspek | PBKDF2 | Argon2id |
|-------|--------|----------|
| Tersedia di OpenSSL | ✅ | ❌ (butuh libargon2) |
| Memory-hard | ❌ | ✅ |
| GPU resistance | Lemah | Kuat |
| NIST approved | ✅ | Tidak (tapi IETF RFC 9106) |

**Keputusan:** PBKDF2-600k dipilih karena keterbatasan dependency. Argon2id adalah upgrade yang direkomendasikan jika libargon2 tersedia.

### Kenapa metadata dienkripsi secara terpisah?

Metadata (filename, timestamp) dienkripsi dengan kunci berbeda (domain-separated) agar:
1. Kehilangan metadata integrity tidak memungkinkan oracle attack pada kunci utama
2. Metadata bisa dihapus/ditambah tanpa re-encrypt ciphertext utama (roadmap)

### AAD mencakup metadata_len field

Jika `metadata_len` tidak diautentikasi, attacker bisa:
- Hapus metadata block → program salah interpret ciphertext sebagai metadata
- Tambah byte palsu → program skip ke ciphertext yang salah offset

Dengan memasukkan `metadata_len` dalam AAD, setiap modifikasi terdeteksi.

---

## Batasan yang Diketahui

### 1. KDF bukan memory-hard

PBKDF2 rentan terhadap GPU/ASIC brute-force lebih dari Argon2id. Untuk password pendek atau lemah, ini signifikan.

**Mitigasi:** Gunakan password ≥16 karakter dengan campuran karakter.

### 2. Tidak ada forward secrecy

File terenkripsi dengan password yang sama. Jika password bocor di masa depan, semua file lama bisa didekripsi.

**Mitigasi:** `rotate-key` command untuk re-encrypt dengan password baru.

### 3. Tidak ada proteksi metadata dari `info` command

Salt dan nonce ditampilkan oleh `info` command. Ini tidak mengancam kerahasiaan data, tapi bisa digunakan untuk fingerprinting.

### 4. Tidak ada proteksi dari attacker dengan akses OS

Jika attacker punya akses ke sistem yang menjalankan SecureVault:
- Password bisa dicapture sebelum hashing
- Plaintext bisa diread dari memory setelah dekripsi
- File plaintext sementara bisa dibaca sebelum dihapus

**Ini di luar scope tool ini.** Full-disk encryption diperlukan untuk threat model ini.

### 5. Integer overflow protection terbatas

Header parser memvalidasi ukuran, tapi beberapa edge case pada filesystem yang sangat besar belum ditest.

---

## Rekomendasi Penggunaan

1. **Gunakan password ≥16 karakter** dengan campuran huruf, angka, simbol
2. **Simpan password di password manager**, bukan file teks
3. **Jangan enkripsi ke file yang sama** dengan input (gunakan output path berbeda)
4. **Verifikasi dekripsi** sebelum menghapus original
5. **Backup kunci/password** — tidak ada recovery jika password hilang

---
