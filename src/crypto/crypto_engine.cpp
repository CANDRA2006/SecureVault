/**
 * crypto_engine.cpp — AES-256-GCM encryption + PBKDF2-HMAC-SHA256 KDF
 *
 * Fixes applied vs original:
 *  - serialize_header() extracted (DRY): used in both encrypt & decrypt
 *  - Metadata decrypt failure now sets result.metadata_corrupt = true
 *    instead of silently returning nullopt with OK status
 *  - Timestamp deserialization byte-order fixed (was big-endian, now LE)
 *  - Metadata domain separation upgraded to HMAC-SHA256(salt, label)
 *  - Input safety limits enforced (password length, plaintext size)
 *  - All error paths leave sensitive buffers zeroed
 */

#include "crypto_engine.h"
#include "secure_mem.h"
#include "vault_format.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

#include <cstring>
#include <cassert>
#include <algorithm>

namespace vault {

// ── Error strings 

const char* error_str(CryptoError e) noexcept {
    switch (e) {
        case CryptoError::OK:                  return "success";
        case CryptoError::BAD_MAGIC:           return "not a vault file";
        case CryptoError::BAD_VERSION:         return "unsupported format version";
        case CryptoError::BAD_ALGORITHM:       return "unsupported algorithm";
        case CryptoError::BAD_HEADER_CORRUPT:  return "header corrupt or truncated";
        case CryptoError::BAD_ITERATIONS:      return "KDF iteration count out of range";
        case CryptoError::AUTHENTICATION_FAILED:
            return "authentication failed (wrong password or corrupt data)";
        case CryptoError::KDF_FAILED:          return "key derivation failed";
        case CryptoError::ENCRYPT_FAILED:      return "encryption error";
        case CryptoError::DECRYPT_FAILED:      return "decryption error";
        case CryptoError::IO_ERROR:            return "I/O error";
        case CryptoError::INVALID_INPUT:       return "invalid input";
        case CryptoError::METADATA_TOO_LARGE:  return "metadata too large";
        case CryptoError::INPUT_TOO_LARGE:     return "input exceeds size limit";
    }
    return "unknown error";
}

// ── SecureKey ────

SecureKey::SecureKey(size_t len) : buf_(len, 0) {}

SecureKey::~SecureKey() {
    secure_zero(buf_.data(), buf_.size());
}

// ── CSPRNG ───────

bool csprng_fill(uint8_t* buf, size_t len) noexcept {
    return RAND_bytes(buf, static_cast<int>(len)) == 1;
}

// ── KDF ──────────

CryptoError pbkdf2_derive(
    const std::string& password,
    const uint8_t*     salt,
    size_t             salt_len,
    uint32_t           iterations,
    SecureKey&         out_key
) noexcept {
    if (iterations < KDF_ITER_MIN || iterations > KDF_ITER_MAX)
        return CryptoError::BAD_ITERATIONS;
    if (out_key.size() != KEY_LEN)
        return CryptoError::KDF_FAILED;
    if (password.size() > MAX_PASSWORD_LEN)
        return CryptoError::INPUT_TOO_LARGE;

    int rc = PKCS5_PBKDF2_HMAC(
        password.c_str(),
        static_cast<int>(password.size()),
        salt,
        static_cast<int>(salt_len),
        static_cast<int>(iterations),
        EVP_sha256(),
        static_cast<int>(KEY_LEN),
        out_key.data()
    );

    return (rc == 1) ? CryptoError::OK : CryptoError::KDF_FAILED;
}

// ── Constant-time compare 

bool ct_equal(const uint8_t* a, const uint8_t* b, size_t len) noexcept {
    return CRYPTO_memcmp(a, b, len) == 0;
}

// ── Metadata serialization 

// TLV: [u8 fname_len][fname bytes][u64 timestamp_le]
std::vector<uint8_t> serialize_metadata(const Metadata& m) {
    std::string fname = m.original_filename.substr(0, 255);
    std::vector<uint8_t> out;
    out.reserve(1 + fname.size() + 8);

    out.push_back(static_cast<uint8_t>(fname.size()));
    for (char c : fname) out.push_back(static_cast<uint8_t>(c));

    // Write timestamp as little-endian uint64
    uint64_t ts = m.timestamp_unix;
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<uint8_t>(ts & 0xFF));
        ts >>= 8;
    }
    return out;
}

std::optional<Metadata> deserialize_metadata(const uint8_t* buf, size_t len) {
    if (len < 9) return std::nullopt; // min: 1-byte len + 0-byte fname + 8-byte ts

    uint8_t fname_len = buf[0];
    if (static_cast<size_t>(1 + fname_len + 8) > len) return std::nullopt;

    Metadata m;
    m.original_filename.assign(reinterpret_cast<const char*>(buf + 1), fname_len);

    // FIX: Read timestamp as little-endian (was incorrectly read as big-endian)
    // Write order: buf[0]=LSB, buf[7]=MSB → read same way
    uint64_t ts = 0;
    for (int i = 0; i < 8; ++i)
        ts |= static_cast<uint64_t>(buf[1 + fname_len + i]) << (i * 8);
    m.timestamp_unix = ts;

    return m;
}

// ── Internal helpers 

namespace {

void write_u32le(uint8_t* buf, uint32_t v) noexcept {
    buf[0] =  v        & 0xFF;
    buf[1] = (v >>  8) & 0xFF;
    buf[2] = (v >> 16) & 0xFF;
    buf[3] = (v >> 24) & 0xFF;
}

uint32_t read_u32le(const uint8_t* buf) noexcept {
    return  static_cast<uint32_t>(buf[0])
          | (static_cast<uint32_t>(buf[1]) <<  8)
          | (static_cast<uint32_t>(buf[2]) << 16)
          | (static_cast<uint32_t>(buf[3]) << 24);
}

/**
 * aes_gcm_encrypt: plaintext → ciphertext + 16-byte tag appended.
 */
bool aes_gcm_encrypt(
    const uint8_t* key,    size_t /*key_len*/,
    const uint8_t* nonce,  size_t nonce_len,
    const uint8_t* aad,    size_t aad_len,
    const uint8_t* plain,  size_t plain_len,
    std::vector<uint8_t>&  out
) noexcept {
    out.clear();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    bool ok = false;
    do {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(),
                               nullptr, nullptr, nullptr) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                static_cast<int>(nonce_len), nullptr) != 1) break;
        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1) break;

        int len = 0;
        if (aad_len > 0) {
            if (EVP_EncryptUpdate(ctx, nullptr, &len,
                                  aad, static_cast<int>(aad_len)) != 1) break;
        }

        out.resize(plain_len + TAG_LEN);
        if (plain_len > 0) {
            if (EVP_EncryptUpdate(ctx, out.data(), &len,
                                  plain, static_cast<int>(plain_len)) != 1) break;
        }

        int final_len = 0;
        if (EVP_EncryptFinal_ex(ctx, out.data() + len, &final_len) != 1) break;

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                                 TAG_LEN, out.data() + plain_len) != 1) break;
        ok = true;
    } while (false);

    EVP_CIPHER_CTX_free(ctx);
    if (!ok) {
        secure_zero(out.data(), out.size());
        out.clear();
    }
    return ok;
}

/**
 * aes_gcm_decrypt: ciphertext (with 16-byte tag appended) → plaintext.
 * Returns false if tag verification fails (authentication error).
 */
bool aes_gcm_decrypt(
    const uint8_t* key,    size_t /*key_len*/,
    const uint8_t* nonce,  size_t nonce_len,
    const uint8_t* aad,    size_t aad_len,
    const uint8_t* cipher, size_t cipher_len,
    std::vector<uint8_t>&  out
) noexcept {
    if (cipher_len < TAG_LEN) return false;
    size_t ct_len       = cipher_len - TAG_LEN;
    const uint8_t* tag_ptr = cipher + ct_len;

    out.clear();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    bool ok = false;
    do {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(),
                               nullptr, nullptr, nullptr) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                 static_cast<int>(nonce_len), nullptr) != 1) break;
        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1) break;

        int len = 0;
        if (aad_len > 0) {
            if (EVP_DecryptUpdate(ctx, nullptr, &len,
                                  aad, static_cast<int>(aad_len)) != 1) break;
        }

        out.resize(ct_len);
        if (ct_len > 0) {
            if (EVP_DecryptUpdate(ctx, out.data(), &len,
                                  cipher, static_cast<int>(ct_len)) != 1) break;
        }

        // Set expected tag BEFORE calling Final
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                                 TAG_LEN,
                                 const_cast<uint8_t*>(tag_ptr)) != 1) break;

        int final_len = 0;
        // Returns 0 if tag mismatch
        if (EVP_DecryptFinal_ex(ctx, out.data() + len, &final_len) != 1) {
            secure_zero(out.data(), out.size());
            out.clear();
            break;
        }
        ok = true;
    } while (false);

    EVP_CIPHER_CTX_free(ctx);
    if (!ok && !out.empty()) {
        secure_zero(out.data(), out.size());
        out.clear();
    }
    return ok;
}

/**
 * Derive domain-separated metadata key using HMAC-SHA256.
 *
 * FIX: Old code XOR'd only the last salt byte (weak domain separation).
 * New code: meta_salt = HMAC-SHA256(salt, "SecureVault-Metadata-v1")
 * which produces a completely independent 32-byte salt for metadata KDF.
 */
bool derive_meta_salt(const uint8_t* salt, uint8_t* meta_salt) noexcept {
    static const char label[] = "SecureVault-Metadata-v1";
    unsigned int out_len = SALT_LEN;
    const uint8_t* result = HMAC(
        EVP_sha256(),
        salt, SALT_LEN,
        reinterpret_cast<const uint8_t*>(label), sizeof(label) - 1,
        meta_salt, &out_len
    );
    return (result != nullptr && out_len == SALT_LEN);
}

} // anonymous namespace

// ── serialize_header (DRY: shared by encrypt + decrypt) ───────────────────

std::vector<uint8_t> serialize_header(const FileHeader& hdr) noexcept {
    std::vector<uint8_t> bytes(FIXED_HEADER_LEN, 0);
    std::memcpy(bytes.data(),      hdr.magic,    4);
    bytes[4] = hdr.version;
    bytes[5] = hdr.algorithm;
    bytes[6] = 0; bytes[7] = 0; // flags always 0
    write_u32le(bytes.data() + 8,  hdr.kdf_iterations);
    std::memcpy(bytes.data() + 12, hdr.salt,     SALT_LEN);
    std::memcpy(bytes.data() + 44, hdr.nonce,    NONCE_LEN);
    write_u32le(bytes.data() + 56, hdr.metadata_len);
    return bytes;
}

// ── vault_parse_header 

std::pair<FileHeader, CryptoError>
vault_parse_header(const std::vector<uint8_t>& blob) noexcept {
    FileHeader hdr{};
    auto fail = [&hdr](CryptoError e) {
        return std::make_pair(hdr, e);
    };

    if (blob.size() < FIXED_HEADER_LEN + TAG_LEN)
        return fail(CryptoError::BAD_HEADER_CORRUPT);

    if (std::memcmp(blob.data(), MAGIC, 4) != 0)
        return fail(CryptoError::BAD_MAGIC);

    std::memcpy(hdr.magic, blob.data(), 4);
    hdr.version   = blob[4];
    hdr.algorithm = blob[5];
    hdr.flags     = static_cast<uint16_t>(blob[6])
                  | (static_cast<uint16_t>(blob[7]) << 8);

    if (hdr.version != FORMAT_VERSION)
        return fail(CryptoError::BAD_VERSION);
    if (hdr.algorithm != ALGO_AES256GCM)
        return fail(CryptoError::BAD_ALGORITHM);

    hdr.kdf_iterations = read_u32le(blob.data() + 8);
    if (hdr.kdf_iterations < KDF_ITER_MIN || hdr.kdf_iterations > KDF_ITER_MAX)
        return fail(CryptoError::BAD_ITERATIONS);

    std::memcpy(hdr.salt,  blob.data() + 12, SALT_LEN);
    std::memcpy(hdr.nonce, blob.data() + 44, NONCE_LEN);
    hdr.metadata_len = read_u32le(blob.data() + 56);

    // Guard against malformed metadata_len causing integer overflow
    uint64_t required = static_cast<uint64_t>(FIXED_HEADER_LEN)
                      + hdr.metadata_len
                      + TAG_LEN;
    if (required > blob.size())
        return fail(CryptoError::BAD_HEADER_CORRUPT);

    return {hdr, CryptoError::OK};
}

// ── vault_encrypt 

std::pair<std::vector<uint8_t>, CryptoError>
vault_encrypt(const std::vector<uint8_t>& plaintext,
              const EncryptParams&        params) noexcept {
    using R = std::pair<std::vector<uint8_t>, CryptoError>;
    auto fail = [](CryptoError e) -> R { return {{}, e}; };

    // Input validation
    if (params.password.empty() || params.password.size() > MAX_PASSWORD_LEN)
        return fail(CryptoError::INVALID_INPUT);
    if (params.iterations < KDF_ITER_MIN || params.iterations > KDF_ITER_MAX)
        return fail(CryptoError::BAD_ITERATIONS);
    if (plaintext.size() > MAX_FILE_SIZE)
        return fail(CryptoError::INPUT_TOO_LARGE);

    // 1. Build header
    FileHeader hdr{};
    std::memcpy(hdr.magic, MAGIC, 4);
    hdr.version        = FORMAT_VERSION;
    hdr.algorithm      = ALGO_AES256GCM;
    hdr.flags          = 0;
    hdr.kdf_iterations = params.iterations;

    // 2. Generate salt + nonce
    if (!csprng_fill(hdr.salt,  SALT_LEN))  return fail(CryptoError::ENCRYPT_FAILED);
    if (!csprng_fill(hdr.nonce, NONCE_LEN)) return fail(CryptoError::ENCRYPT_FAILED);

    // 3. Serialize + encrypt optional metadata
    std::vector<uint8_t> enc_metadata_block;

    if (params.metadata.has_value()) {
        auto raw_meta = serialize_metadata(*params.metadata);
        if (raw_meta.size() > 64 * 1024) return fail(CryptoError::METADATA_TOO_LARGE);

        // Domain-separated metadata key via HMAC-derived salt
        uint8_t meta_salt[SALT_LEN];
        if (!derive_meta_salt(hdr.salt, meta_salt))
            return fail(CryptoError::KDF_FAILED);

        SecureKey meta_key(KEY_LEN);
        if (pbkdf2_derive(params.password, meta_salt, SALT_LEN,
                          params.iterations, meta_key) != CryptoError::OK)
            return fail(CryptoError::KDF_FAILED);

        uint8_t meta_nonce[NONCE_LEN];
        if (!csprng_fill(meta_nonce, NONCE_LEN)) return fail(CryptoError::ENCRYPT_FAILED);

        std::vector<uint8_t> enc_meta;
        if (!aes_gcm_encrypt(meta_key.data(), KEY_LEN,
                              meta_nonce, NONCE_LEN,
                              nullptr, 0,
                              raw_meta.data(), raw_meta.size(),
                              enc_meta))
            return fail(CryptoError::ENCRYPT_FAILED);

        enc_metadata_block.insert(enc_metadata_block.end(),
                                   meta_nonce, meta_nonce + NONCE_LEN);
        enc_metadata_block.insert(enc_metadata_block.end(),
                                   enc_meta.begin(), enc_meta.end());
    }

    if (enc_metadata_block.size() > UINT32_MAX)
        return fail(CryptoError::METADATA_TOO_LARGE);
    hdr.metadata_len = static_cast<uint32_t>(enc_metadata_block.size());

    // 4. Serialize header to portable LE bytes (shared helper)
    std::vector<uint8_t> hdr_bytes = serialize_header(hdr);

    // 5. Derive main encryption key
    SecureKey key(KEY_LEN);
    if (pbkdf2_derive(params.password, hdr.salt, SALT_LEN,
                      params.iterations, key) != CryptoError::OK)
        return fail(CryptoError::KDF_FAILED);

    // 6. Encrypt plaintext with full header as AAD
    std::vector<uint8_t> ciphertext;
    if (!aes_gcm_encrypt(key.data(), KEY_LEN,
                         hdr.nonce, NONCE_LEN,
                         hdr_bytes.data(), FIXED_HEADER_LEN,
                         plaintext.data(), plaintext.size(),
                         ciphertext))
        return fail(CryptoError::ENCRYPT_FAILED);

    // 7. Assemble: header || metadata_block || ciphertext(+tag)
    std::vector<uint8_t> output;
    output.reserve(FIXED_HEADER_LEN + enc_metadata_block.size() + ciphertext.size());
    output.insert(output.end(), hdr_bytes.begin(),        hdr_bytes.end());
    output.insert(output.end(), enc_metadata_block.begin(), enc_metadata_block.end());
    output.insert(output.end(), ciphertext.begin(),       ciphertext.end());

    return {std::move(output), CryptoError::OK};
}

// ── vault_decrypt 

std::pair<DecryptResult, CryptoError>
vault_decrypt(const std::vector<uint8_t>& blob,
              const std::string&          password) noexcept {
    DecryptResult result{};
    auto fail = [&result](CryptoError e) {
        return std::make_pair(result, e);
    };

    // Input validation
    if (password.empty() || password.size() > MAX_PASSWORD_LEN)
        return fail(CryptoError::INVALID_INPUT);

    auto [hdr, parse_err] = vault_parse_header(blob);
    if (parse_err != CryptoError::OK) return fail(parse_err);

    // Re-serialize header bytes for AAD using shared helper (must match encrypt)
    std::vector<uint8_t> hdr_bytes = serialize_header(hdr);

    // Derive main key
    SecureKey key(KEY_LEN);
    if (pbkdf2_derive(password, hdr.salt, SALT_LEN,
                      hdr.kdf_iterations, key) != CryptoError::OK)
        return fail(CryptoError::KDF_FAILED);

    // Ciphertext starts after fixed header + metadata block
    size_t ct_offset = FIXED_HEADER_LEN + hdr.metadata_len;
    if (ct_offset >= blob.size()) return fail(CryptoError::BAD_HEADER_CORRUPT);
    size_t ct_len    = blob.size() - ct_offset;

    if (!aes_gcm_decrypt(key.data(), KEY_LEN,
                         hdr.nonce, NONCE_LEN,
                         hdr_bytes.data(), FIXED_HEADER_LEN,
                         blob.data() + ct_offset, ct_len,
                         result.plaintext))
        return fail(CryptoError::AUTHENTICATION_FAILED);

    // Decrypt optional metadata
    if (hdr.metadata_len > 0) {
        constexpr size_t META_OVERHEAD = NONCE_LEN + TAG_LEN;

        if (hdr.metadata_len <= META_OVERHEAD) {
            // Block is too small to be valid — metadata was corrupted/tampered
            result.metadata_corrupt = true;
        } else {
            const uint8_t* meta_block  = blob.data() + FIXED_HEADER_LEN;
            const uint8_t* meta_nonce  = meta_block;
            const uint8_t* meta_ct     = meta_block + NONCE_LEN;
            size_t         meta_ct_len = hdr.metadata_len - NONCE_LEN;

            // Domain-separated metadata key (must match encrypt path)
            uint8_t meta_salt[SALT_LEN];
            if (!derive_meta_salt(hdr.salt, meta_salt)) {
                result.metadata_corrupt = true;
            } else {
                SecureKey meta_key(KEY_LEN);
                if (pbkdf2_derive(password, meta_salt, SALT_LEN,
                                  hdr.kdf_iterations, meta_key) != CryptoError::OK) {
                    result.metadata_corrupt = true;
                } else {
                    std::vector<uint8_t> meta_plain;
                    if (!aes_gcm_decrypt(meta_key.data(), KEY_LEN,
                                         meta_nonce, NONCE_LEN,
                                         nullptr, 0,
                                         meta_ct, meta_ct_len,
                                         meta_plain)) {
                        // FIX: Authentication failure on metadata block is now
                        // explicitly surfaced instead of silently ignored.
                        result.metadata_corrupt = true;
                    } else {
                        result.metadata = deserialize_metadata(
                            meta_plain.data(), meta_plain.size());
                        secure_zero(meta_plain.data(), meta_plain.size());
                    }
                }
            }
        }
    }

    return {std::move(result), CryptoError::OK};
}

} // namespace vault