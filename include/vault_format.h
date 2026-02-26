#pragma once
/**
 * vault_format.h — SecureVault versioned binary file format
 *
 * Binary layout (all integers little-endian):
 *   [0..3]   Magic bytes: 0x53 0x56 0x4C 0x54  ("SVLT")
 *   [4]      Format version: 0x01
 *   [5]      Algorithm ID:   0x01 = AES-256-GCM
 *   [6..7]   Header flags (reserved, must be 0)
 *   [8..11]  KDF iterations (uint32_t)
 *   [12..43] Salt (32 bytes, CSPRNG)
 *   [44..55] Nonce/IV (12 bytes, CSPRNG)
 *   [56..59] Metadata length in bytes (uint32_t, 0 = no metadata)
 *   [60..]   Encrypted metadata (if metadata_len > 0)
 *            metadata nonce (12 bytes) precedes the metadata ciphertext+tag
 *   [..]     Ciphertext (plaintext XOR keystream via AES-256-GCM)
 *   [last 16] GCM authentication tag (16 bytes)
 *
 * The GCM AAD (additional authenticated data) covers bytes [0..55]
 * of the header so that any tampering with header fields is detected.
 */

#include <cstdint>
#include <cstddef>
#include <array>

namespace vault {

// ── Constants ─────────────────────────────────────────────────────────────

constexpr uint8_t  MAGIC[4]        = {0x53, 0x56, 0x4C, 0x54}; // "SVLT"
constexpr uint8_t  FORMAT_VERSION  = 0x01;
constexpr uint8_t  ALGO_AES256GCM  = 0x01;

constexpr size_t   SALT_LEN        = 32;
constexpr size_t   NONCE_LEN       = 12;   // 96-bit GCM nonce
constexpr size_t   TAG_LEN         = 16;   // 128-bit GCM tag
constexpr size_t   KEY_LEN         = 32;   // AES-256

// Fixed header size (without variable metadata block)
constexpr size_t   FIXED_HEADER_LEN = 60;
// Byte offset where the ciphertext begins (after fixed header + metadata block)
// Computed at parse time once metadata_len is known.

// KDF defaults (PBKDF2-HMAC-SHA256)
constexpr uint32_t KDF_ITER_DEFAULT = 600'000; // NIST 2023 recommendation
constexpr uint32_t KDF_ITER_MIN     = 100'000;
constexpr uint32_t KDF_ITER_MAX     = 10'000'000;

// ── On-disk header (fixed portion, packed, no padding) ────────────────────
#pragma pack(push, 1)
struct FileHeader {
    uint8_t  magic[4];          // SVLT
    uint8_t  version;           // FORMAT_VERSION
    uint8_t  algorithm;         // ALGO_*
    uint16_t flags;             // reserved, must be 0
    uint32_t kdf_iterations;    // PBKDF2 iterations
    uint8_t  salt[SALT_LEN];   // 32-byte random salt
    uint8_t  nonce[NONCE_LEN]; // 12-byte random GCM nonce
    uint32_t metadata_len;     // byte count of encrypted metadata block (may be 0)
    // After this struct: metadata_len bytes of encrypted metadata (with its own 12-byte nonce + 16-byte tag)
    // Then: ciphertext bytes
    // Then: 16-byte GCM authentication tag
};
#pragma pack(pop)

static_assert(sizeof(FileHeader) == FIXED_HEADER_LEN,
    "FileHeader size mismatch — check pack/alignment");

// ── Metadata (plaintext, encrypted separately) ────────────────────────────
struct Metadata {
    std::string original_filename; // UTF-8, max 255 bytes
    uint64_t    timestamp_unix{0}; // seconds since epoch
};

} // namespace vault