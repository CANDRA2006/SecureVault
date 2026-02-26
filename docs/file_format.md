# SecureVault File Format Specification

**Format name:** SVLT (SecureVault)
**Current version:** 1 (0x01)
**Endianness:** Little-endian untuk semua integer multi-byte

---

## Gambaran Umum

File vault adalah blob biner dengan struktur:

```
┌──────────────────────────┐
│      Fixed Header        │  60 bytes
│  (magic, version, KDF,   │
│   salt, nonce, meta_len) │
├──────────────────────────┤
│   Encrypted Metadata     │  metadata_len bytes (0 jika tidak ada)
│   (nonce + ct + tag)     │
├──────────────────────────┤
│      Ciphertext          │  N bytes (sama dengan panjang plaintext)
├──────────────────────────┤
│    GCM Auth Tag          │  16 bytes
└──────────────────────────┘
```

---

## Fixed Header (60 bytes)

| Offset | Size | Type | Nilai / Deskripsi |
|--------|------|------|-------------------|
| 0 | 4 | bytes | Magic: `0x53 0x56 0x4C 0x54` ("SVLT" ASCII) |
| 4 | 1 | uint8 | Format version: `0x01` |
| 5 | 1 | uint8 | Algorithm ID: `0x01` = AES-256-GCM |
| 6 | 2 | uint16 LE | Flags: reserved, harus `0x0000` |
| 8 | 4 | uint32 LE | KDF iterations (PBKDF2 iteration count) |
| 12 | 32 | bytes | Salt (random, dari CSPRNG OS) |
| 44 | 12 | bytes | GCM Nonce/IV (random, dari CSPRNG OS) |
| 56 | 4 | uint32 LE | Metadata block length (byte, 0 = tidak ada metadata) |

**Total fixed header: 60 bytes**

### Validasi Header

Parser harus memvalidasi urutan berikut:

1. Panjang blob ≥ 60 + metadata_len + 16 (minimum: header + empty ct + tag)
2. Magic bytes harus persis `53 56 4C 54`
3. Version harus `0x01` (atau versi yang dikenal)
4. Algorithm ID harus nilai yang dikenal (`0x01`)
5. `kdf_iterations` harus dalam rentang `[100000, 10000000]`
6. `metadata_len + FIXED_HEADER_LEN + TAG_LEN ≤ total_size` (cegah overflow)

---

## Additional Authenticated Data (AAD)

GCM AAD = **seluruh fixed header 60 bytes**.

Ini berarti modifikasi apapun terhadap magic, version, algorithm, iterations, salt, nonce, atau metadata_len akan menyebabkan dekripsi gagal dengan authentication error.

---

## Encrypted Metadata Block

Jika `metadata_len > 0`, byte `[60 .. 60+metadata_len-1]` berisi blok metadata terenkripsi:

```
┌──────────────────────────────────────────────────────────┐
│  Metadata Nonce (12 bytes)                               │
│  Metadata Ciphertext (metadata_len - 12 - 16 bytes)      │
│  Metadata GCM Tag (16 bytes)                             │
└──────────────────────────────────────────────────────────┘
```

Minimum `metadata_len` yang valid jika ada = 12 + 0 + 16 = 28 bytes.

### Metadata Key (Domain Separation)

Metadata dienkripsi dengan kunci terpisah untuk mencegah any key reuse:

```
meta_salt = salt[0..30] || (salt[31] XOR 0x01)
meta_key  = PBKDF2-HMAC-SHA256(password, meta_salt, iterations)
```

### Plaintext Metadata Format (TLV sederhana)

| Offset | Size | Deskripsi |
|--------|------|-----------|
| 0 | 1 | Panjang filename (uint8, 0-255) |
| 1 | N | Original filename (UTF-8, N bytes) |
| 1+N | 8 | Timestamp Unix (uint64 LE, detik sejak epoch) |

---

## Ciphertext + Tag

Dimulai dari offset `60 + metadata_len`.

```
ciphertext_offset = 60 + metadata_len
ciphertext_len    = total_size - ciphertext_offset - 16
tag               = blob[total_size-16 .. total_size-1]
```

GCM tidak menambah padding — panjang ciphertext = panjang plaintext.

---

## Algorithm IDs

| ID | Algoritma |
|----|-----------|
| 0x01 | AES-256-GCM (nonce 12 bytes, tag 16 bytes) |
| 0x02–0xFF | Reserved untuk versi mendatang |

---

## Version Compatibility

| Version | Deskripsi |
|---------|-----------|
| 0x01 | Format awal. AES-256-GCM, PBKDF2-SHA256. |

Jika version tidak dikenal, implementasi harus menolak file dengan error `BAD_VERSION`.

---

## Contoh Hexdump (file kecil)

```
Offset  Data                                    Arti
00000   53 56 4C 54                             Magic "SVLT"
00004   01                                      Version 1
00005   01                                      AES-256-GCM
00006   00 00                                   Flags (0)
00008   A0 86 01 00                             100000 iter (LE)
0000C   [32 bytes salt]                         Random salt
0002C   [12 bytes nonce]                        Random nonce
00038   33 00 00 00                             metadata_len = 51
0003C   [51 bytes encrypted metadata]           nonce+ct+tag
0006F   [N bytes ciphertext]                    AES-256-GCM output
...     [16 bytes GCM tag]                      Auth tag
```