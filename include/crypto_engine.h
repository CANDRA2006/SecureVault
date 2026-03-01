#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <optional>
#include "vault_format.h"

namespace vault {

// ── Error type 
enum class CryptoError {
    OK = 0,
    BAD_MAGIC,
    BAD_VERSION,
    BAD_ALGORITHM,
    BAD_HEADER_CORRUPT,
    BAD_ITERATIONS,
    AUTHENTICATION_FAILED,  // AEAD tag mismatch
    KDF_FAILED,
    ENCRYPT_FAILED,
    DECRYPT_FAILED,
    IO_ERROR,
    INVALID_INPUT,
    METADATA_TOO_LARGE,
    INPUT_TOO_LARGE,        // file or password exceeds safety limit
};

const char* error_str(CryptoError e) noexcept;

// ── Secure key buffer (RAII + zeroize)
class SecureKey {
public:
    explicit SecureKey(size_t len);
    ~SecureKey();

    SecureKey(const SecureKey&)            = delete;
    SecureKey& operator=(const SecureKey&) = delete;

    uint8_t*       data()       noexcept { return buf_.data(); }
    const uint8_t* data() const noexcept { return buf_.data(); }
    size_t         size() const noexcept { return buf_.size(); }

private:
    std::vector<uint8_t> buf_;
};

// ── CSPRNG 
/// Fill buffer with cryptographically secure random bytes (via OS).
bool csprng_fill(uint8_t* buf, size_t len) noexcept;

// ── KDF 
CryptoError pbkdf2_derive(
    const std::string& password,
    const uint8_t*     salt,
    size_t             salt_len,
    uint32_t           iterations,
    SecureKey&         out_key
) noexcept;

// ── Constant-time compare 
/// Returns true iff a[0..len-1] == b[0..len-1], in constant time.
bool ct_equal(const uint8_t* a, const uint8_t* b, size_t len) noexcept;

// ── Serialized metadata helpers 
std::vector<uint8_t> serialize_metadata(const Metadata& m);
std::optional<Metadata> deserialize_metadata(const uint8_t* buf, size_t len);

// ── Core operations 
struct EncryptParams {
    std::string  password;
    uint32_t     iterations   = KDF_ITER_DEFAULT;
    std::optional<Metadata> metadata;
    bool         no_metadata  = false;
};

struct DecryptResult {
    std::vector<uint8_t>    plaintext;
    std::optional<Metadata> metadata;
    /**
     * True if a metadata block was present in the file but its GCM tag
     * failed to verify. This indicates the metadata was tampered with.
     * The main ciphertext authenticated successfully, so plaintext is valid,
     * but the caller SHOULD warn the user.
     */
    bool metadata_corrupt = false;
};

/**
 * Encrypt plaintext → versioned vault ciphertext blob.
 */
std::pair<std::vector<uint8_t>, CryptoError>
vault_encrypt(const std::vector<uint8_t>& plaintext,
              const EncryptParams&        params) noexcept;

/**
 * Decrypt vault ciphertext blob → plaintext.
 * Check result.metadata_corrupt to detect metadata tampering.
 */
std::pair<DecryptResult, CryptoError>
vault_decrypt(const std::vector<uint8_t>& ciphertext,
              const std::string&          password) noexcept;

/**
 * Parse only the header (for `info` command) — does NOT decrypt.
 */
std::pair<FileHeader, CryptoError>
vault_parse_header(const std::vector<uint8_t>& blob) noexcept;

/**
 * Serialize FileHeader to portable little-endian bytes.
 * Used internally by both encrypt and decrypt to build AAD consistently.
 */
std::vector<uint8_t> serialize_header(const FileHeader& hdr) noexcept;

} // namespace vault