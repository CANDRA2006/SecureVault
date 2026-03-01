/**
  *
 * Updated for fixed API:
 *  - DecryptResult now has metadata_corrupt field
 *  - Timestamp deserialization byte-order fix verified
 *  - Metadata tampering detection tested explicitly
 */

#include "crypto_engine.h"
#include "secure_mem.h"
#include "vault_format.h"

#include <iostream>
#include <vector>
#include <string>
#include <cassert>
#include <cstring>
#include <chrono>

// ── Test framework 

static int g_passed = 0;
static int g_failed = 0;

#define TEST(name) void test_##name()
#define RUN(name)  do { \
    std::cout << "[ RUN  ] " #name "\n"; \
    try { test_##name(); std::cout << "[ PASS ] " #name "\n"; ++g_passed; } \
    catch (const std::exception& e) { \
        std::cout << "[ FAIL ] " #name " — " << e.what() << "\n"; ++g_failed; } \
    catch (...) { \
        std::cout << "[ FAIL ] " #name " — unknown exception\n"; ++g_failed; } \
} while(0)

#define ASSERT(cond) do { \
    if (!(cond)) throw std::runtime_error("Assertion failed: " #cond \
        " at line " + std::to_string(__LINE__)); \
} while(0)

#define ASSERT_EQ(a, b) do { \
    if ((a) != (b)) throw std::runtime_error( \
        std::string("ASSERT_EQ failed: " #a " != " #b) \
        + " at line " + std::to_string(__LINE__)); \
} while(0)

// ── Helper 

static vault::EncryptParams make_params(const std::string& pw,
                                        bool metadata = false) {
    vault::EncryptParams p;
    p.password   = pw;
    p.iterations = vault::KDF_ITER_MIN;
    if (metadata) {
        vault::Metadata m;
        m.original_filename = "test_file.txt";
        m.timestamp_unix    = 1700000000ULL;
        p.metadata = m;
    }
    return p;
}

// CSPRNG
TEST(csprng_returns_success) {
    uint8_t buf[32]{};
    ASSERT(vault::csprng_fill(buf, 32));
}

TEST(csprng_produces_nonzero) {
    uint8_t buf[32]{};
    ASSERT(vault::csprng_fill(buf, 32));
    bool any_nonzero = false;
    for (auto b : buf) if (b) { any_nonzero = true; break; }
    ASSERT(any_nonzero);
}

TEST(csprng_two_calls_differ) {
    uint8_t a[32]{}, b[32]{};
    ASSERT(vault::csprng_fill(a, 32));
    ASSERT(vault::csprng_fill(b, 32));
    ASSERT(std::memcmp(a, b, 32) != 0);
}

//
// KDF
//

TEST(kdf_success) {
    uint8_t salt[32]{};
    vault::csprng_fill(salt, 32);
    vault::SecureKey key(vault::KEY_LEN);
    auto err = vault::pbkdf2_derive("password", salt, 32,
                                    vault::KDF_ITER_MIN, key);
    ASSERT_EQ(err, vault::CryptoError::OK);
}

TEST(kdf_deterministic) {
    uint8_t salt[32];
    std::memset(salt, 0xAA, 32);
    vault::SecureKey k1(vault::KEY_LEN), k2(vault::KEY_LEN);
    vault::pbkdf2_derive("same-pw", salt, 32, vault::KDF_ITER_MIN, k1);
    vault::pbkdf2_derive("same-pw", salt, 32, vault::KDF_ITER_MIN, k2);
    ASSERT(std::memcmp(k1.data(), k2.data(), vault::KEY_LEN) == 0);
}

TEST(kdf_different_passwords_differ) {
    uint8_t salt[32]{};
    vault::SecureKey k1(vault::KEY_LEN), k2(vault::KEY_LEN);
    vault::pbkdf2_derive("pw-one", salt, 32, vault::KDF_ITER_MIN, k1);
    vault::pbkdf2_derive("pw-two", salt, 32, vault::KDF_ITER_MIN, k2);
    ASSERT(std::memcmp(k1.data(), k2.data(), vault::KEY_LEN) != 0);
}

TEST(kdf_different_salts_differ) {
    uint8_t s1[32]{0x11}, s2[32]{0x22};
    vault::SecureKey k1(vault::KEY_LEN), k2(vault::KEY_LEN);
    vault::pbkdf2_derive("same-pw", s1, 32, vault::KDF_ITER_MIN, k1);
    vault::pbkdf2_derive("same-pw", s2, 32, vault::KDF_ITER_MIN, k2);
    ASSERT(std::memcmp(k1.data(), k2.data(), vault::KEY_LEN) != 0);
}

TEST(kdf_rejects_low_iterations) {
    uint8_t salt[32]{};
    vault::SecureKey key(vault::KEY_LEN);
    auto err = vault::pbkdf2_derive("pw", salt, 32, 1000, key);
    ASSERT_EQ(err, vault::CryptoError::BAD_ITERATIONS);
}

TEST(kdf_rejects_too_high_iterations) {
    uint8_t salt[32]{};
    vault::SecureKey key(vault::KEY_LEN);
    auto err = vault::pbkdf2_derive("pw", salt, 32,
                                    vault::KDF_ITER_MAX + 1, key);
    ASSERT_EQ(err, vault::CryptoError::BAD_ITERATIONS);
}

//
// Encrypt / Decrypt roundtrip
//

TEST(roundtrip_basic) {
    std::vector<uint8_t> plain = {0x48, 0x65, 0x6C, 0x6C, 0x6F}; // "Hello"
    auto p = make_params("roundtrip-pw");
    auto [ct, enc_err] = vault::vault_encrypt(plain, p);
    ASSERT_EQ(enc_err, vault::CryptoError::OK);
    auto [res, dec_err] = vault::vault_decrypt(ct, p.password);
    ASSERT_EQ(dec_err, vault::CryptoError::OK);
    ASSERT_EQ(res.plaintext, plain);
}

TEST(roundtrip_empty_plaintext) {
    std::vector<uint8_t> plain;
    auto p = make_params("empty-pw");
    auto [ct, enc_err] = vault::vault_encrypt(plain, p);
    ASSERT_EQ(enc_err, vault::CryptoError::OK);
    auto [res, dec_err] = vault::vault_decrypt(ct, p.password);
    ASSERT_EQ(dec_err, vault::CryptoError::OK);
    ASSERT(res.plaintext.empty());
}

TEST(roundtrip_1kb) {
    std::vector<uint8_t> plain(1024, 0xCC);
    auto p = make_params("1kb-pw");
    auto [ct, enc_err] = vault::vault_encrypt(plain, p);
    ASSERT_EQ(enc_err, vault::CryptoError::OK);
    auto [res, dec_err] = vault::vault_decrypt(ct, p.password);
    ASSERT_EQ(dec_err, vault::CryptoError::OK);
    ASSERT_EQ(res.plaintext, plain);
}

TEST(roundtrip_binary_data) {
    std::vector<uint8_t> plain(256);
    for (int i = 0; i < 256; ++i) plain[i] = static_cast<uint8_t>(i);
    auto p = make_params("binary-pw");
    auto [ct, enc_err] = vault::vault_encrypt(plain, p);
    ASSERT_EQ(enc_err, vault::CryptoError::OK);
    auto [res, dec_err] = vault::vault_decrypt(ct, p.password);
    ASSERT_EQ(dec_err, vault::CryptoError::OK);
    ASSERT_EQ(res.plaintext, plain);
}

TEST(roundtrip_all_zeros) {
    std::vector<uint8_t> plain(64, 0x00);
    auto p = make_params("zeros-pw");
    auto [ct, enc_err] = vault::vault_encrypt(plain, p);
    ASSERT_EQ(enc_err, vault::CryptoError::OK);
    auto [res, dec_err] = vault::vault_decrypt(ct, p.password);
    ASSERT_EQ(dec_err, vault::CryptoError::OK);
    ASSERT_EQ(res.plaintext, plain);
}

TEST(roundtrip_all_0xFF) {
    std::vector<uint8_t> plain(64, 0xFF);
    auto p = make_params("ff-pw");
    auto [ct, enc_err] = vault::vault_encrypt(plain, p);
    ASSERT_EQ(enc_err, vault::CryptoError::OK);
    auto [res, dec_err] = vault::vault_decrypt(ct, p.password);
    ASSERT_EQ(dec_err, vault::CryptoError::OK);
    ASSERT_EQ(res.plaintext, plain);
}

TEST(encrypt_different_runs_produce_different_ct) {
    std::vector<uint8_t> plain = {0x01, 0x02};
    auto p = make_params("diff-pw");
    auto [ct1, e1] = vault::vault_encrypt(plain, p);
    auto [ct2, e2] = vault::vault_encrypt(plain, p);
    ASSERT_EQ(e1, vault::CryptoError::OK);
    ASSERT_EQ(e2, vault::CryptoError::OK);
    // Different random salts/nonces → different ciphertext
    ASSERT(ct1 != ct2);
}

//
// Authentication (tampering detection)
//

TEST(wrong_password_rejected) {
    std::vector<uint8_t> plain = {0xAB};
    auto p = make_params("correct-pw");
    auto [ct, enc_err] = vault::vault_encrypt(plain, p);
    ASSERT_EQ(enc_err, vault::CryptoError::OK);
    auto [res, dec_err] = vault::vault_decrypt(ct, "wrong-pw");
    ASSERT_EQ(dec_err, vault::CryptoError::AUTHENTICATION_FAILED);
}

TEST(empty_password_rejected) {
    std::vector<uint8_t> plain = {0x01};
    auto p = make_params("pw");
    auto [ct, enc_err] = vault::vault_encrypt(plain, p);
    ASSERT_EQ(enc_err, vault::CryptoError::OK);
    auto [res, dec_err] = vault::vault_decrypt(ct, "");
    ASSERT_EQ(dec_err, vault::CryptoError::INVALID_INPUT);
}

TEST(tamper_ciphertext_body_detected) {
    std::vector<uint8_t> plain = {0xDE, 0xAD, 0xBE, 0xEF};
    auto p = make_params("tamper-pw");
    auto [ct, enc_err] = vault::vault_encrypt(plain, p);
    ASSERT_EQ(enc_err, vault::CryptoError::OK);
    ct[vault::FIXED_HEADER_LEN + 2] ^= 0xFF;
    auto [res, dec_err] = vault::vault_decrypt(ct, p.password);
    ASSERT_EQ(dec_err, vault::CryptoError::AUTHENTICATION_FAILED);
}

TEST(tamper_tag_detected) {
    std::vector<uint8_t> plain = {0x01, 0x02, 0x03};
    auto p = make_params("tag-tamper");
    auto [ct, enc_err] = vault::vault_encrypt(plain, p);
    ASSERT_EQ(enc_err, vault::CryptoError::OK);
    ct.back() ^= 0x01; // flip last byte of GCM tag
    auto [res, dec_err] = vault::vault_decrypt(ct, p.password);
    ASSERT_EQ(dec_err, vault::CryptoError::AUTHENTICATION_FAILED);
}

TEST(tamper_salt_detected) {
    std::vector<uint8_t> plain = {0xCA, 0xFE};
    auto p = make_params("salt-tamper");
    auto [ct, enc_err] = vault::vault_encrypt(plain, p);
    ASSERT_EQ(enc_err, vault::CryptoError::OK);
    ct[12] ^= 0x01; // flip a bit in the salt
    auto [res, dec_err] = vault::vault_decrypt(ct, p.password);
    ASSERT_EQ(dec_err, vault::CryptoError::AUTHENTICATION_FAILED);
}

TEST(tamper_nonce_detected) {
    std::vector<uint8_t> plain = {0xBE, 0xEF};
    auto p = make_params("nonce-tamper");
    auto [ct, enc_err] = vault::vault_encrypt(plain, p);
    ASSERT_EQ(enc_err, vault::CryptoError::OK);
    ct[44] ^= 0x01; // flip a bit in the nonce
    auto [res, dec_err] = vault::vault_decrypt(ct, p.password);
    ASSERT_EQ(dec_err, vault::CryptoError::AUTHENTICATION_FAILED);
}

//
// Bad header detection
//

TEST(bad_magic_rejected) {
    std::vector<uint8_t> junk = {0x00, 0x01, 0x02, 0x03,
                                  0x04, 0x05, 0x06, 0x07};
    auto [res, err] = vault::vault_decrypt(junk, "pw");
    ASSERT(err == vault::CryptoError::BAD_MAGIC
        || err == vault::CryptoError::BAD_HEADER_CORRUPT);
}

TEST(truncated_blob_rejected) {
    std::vector<uint8_t> trunc = {0x53, 0x56, 0x4C, 0x54, 0x01};
    auto [res, err] = vault::vault_decrypt(trunc, "pw");
    ASSERT(err == vault::CryptoError::BAD_HEADER_CORRUPT
        || err == vault::CryptoError::BAD_MAGIC);
}

TEST(empty_blob_rejected) {
    std::vector<uint8_t> empty;
    auto [res, err] = vault::vault_decrypt(empty, "pw");
    ASSERT(err != vault::CryptoError::OK);
}

TEST(bad_version_rejected) {
    std::vector<uint8_t> plain = {0x01};
    auto p = make_params("ver-pw");
    auto [ct, enc_err] = vault::vault_encrypt(plain, p);
    ASSERT_EQ(enc_err, vault::CryptoError::OK);
    ct[4] = 0x99; // corrupt version byte
    auto [res, err] = vault::vault_decrypt(ct, p.password);
    ASSERT_EQ(err, vault::CryptoError::BAD_VERSION);
}

TEST(bad_algorithm_rejected) {
    std::vector<uint8_t> plain = {0x01};
    auto p = make_params("algo-pw");
    auto [ct, enc_err] = vault::vault_encrypt(plain, p);
    ASSERT_EQ(enc_err, vault::CryptoError::OK);
    ct[5] = 0xFF; // corrupt algorithm byte
    auto [res, err] = vault::vault_decrypt(ct, p.password);
    ASSERT_EQ(err, vault::CryptoError::BAD_ALGORITHM);
}

//
// Metadata
//

TEST(metadata_roundtrip) {
    std::vector<uint8_t> plain = {0x01};
    auto p = make_params("meta-pw", true);

    auto [ct, enc_err] = vault::vault_encrypt(plain, p);
    ASSERT_EQ(enc_err, vault::CryptoError::OK);

    auto [res, dec_err] = vault::vault_decrypt(ct, p.password);
    ASSERT_EQ(dec_err, vault::CryptoError::OK);
    ASSERT(!res.metadata_corrupt);
    ASSERT(res.metadata.has_value());
    ASSERT_EQ(res.metadata->original_filename, "test_file.txt");
    ASSERT_EQ(res.metadata->timestamp_unix, 1700000000ULL);
}

TEST(metadata_timestamp_byte_order) {
    // Verify the little-endian fix: specific timestamp values
    std::vector<uint8_t> plain = {0xAA};
    vault::EncryptParams p;
    p.password   = "ts-test";
    p.iterations = vault::KDF_ITER_MIN;
    vault::Metadata m;
    m.original_filename = "f";
    m.timestamp_unix    = 0x0102030405060708ULL; // distinct bytes
    p.metadata = m;

    auto [ct, enc_err] = vault::vault_encrypt(plain, p);
    ASSERT_EQ(enc_err, vault::CryptoError::OK);
    auto [res, dec_err] = vault::vault_decrypt(ct, p.password);
    ASSERT_EQ(dec_err, vault::CryptoError::OK);
    ASSERT(!res.metadata_corrupt);
    ASSERT_EQ(res.metadata->timestamp_unix, 0x0102030405060708ULL);
}

TEST(no_metadata_flag) {
    std::vector<uint8_t> plain = {0x42};
    vault::EncryptParams p;
    p.password    = "nometa-pw";
    p.iterations  = vault::KDF_ITER_MIN;
    p.no_metadata = true;

    auto [ct, enc_err] = vault::vault_encrypt(plain, p);
    ASSERT_EQ(enc_err, vault::CryptoError::OK);
    auto [res, dec_err] = vault::vault_decrypt(ct, p.password);
    ASSERT_EQ(dec_err, vault::CryptoError::OK);
    ASSERT(!res.metadata.has_value());
    ASSERT(!res.metadata_corrupt);
}

TEST(metadata_tampering_detected) {
    // FIX verification: metadata block corruption must set metadata_corrupt
    // but NOT fail with AUTHENTICATION_FAILED on main ciphertext
    std::vector<uint8_t> plain = {0xCA, 0xFE};
    auto p = make_params("meta-tamper", true);

    auto [ct, enc_err] = vault::vault_encrypt(plain, p);
    ASSERT_EQ(enc_err, vault::CryptoError::OK);

    // Corrupt a byte inside the metadata block (after fixed header)
    if (ct.size() > vault::FIXED_HEADER_LEN + 5) {
        ct[vault::FIXED_HEADER_LEN + 4] ^= 0xAB;
    }

    auto [res, dec_err] = vault::vault_decrypt(ct, p.password);
    // Main ciphertext OK, but metadata should be flagged
    ASSERT_EQ(dec_err, vault::CryptoError::OK);
    ASSERT(res.metadata_corrupt);
    ASSERT(!res.metadata.has_value());
    // Plaintext should still be valid
    ASSERT_EQ(res.plaintext, plain);
}

TEST(metadata_long_filename) {
    std::vector<uint8_t> plain = {0x01};
    vault::EncryptParams p;
    p.password   = "long-fname";
    p.iterations = vault::KDF_ITER_MIN;
    vault::Metadata m;
    m.original_filename = std::string(255, 'x'); // max length
    m.timestamp_unix    = 42ULL;
    p.metadata = m;

    auto [ct, enc_err] = vault::vault_encrypt(plain, p);
    ASSERT_EQ(enc_err, vault::CryptoError::OK);
    auto [res, dec_err] = vault::vault_decrypt(ct, p.password);
    ASSERT_EQ(dec_err, vault::CryptoError::OK);
    ASSERT(!res.metadata_corrupt);
    ASSERT_EQ(res.metadata->original_filename.size(), 255u);
}

TEST(metadata_zero_timestamp) {
    std::vector<uint8_t> plain = {0x01};
    vault::EncryptParams p;
    p.password   = "zero-ts";
    p.iterations = vault::KDF_ITER_MIN;
    vault::Metadata m;
    m.original_filename = "a";
    m.timestamp_unix    = 0ULL;
    p.metadata = m;

    auto [ct, enc_err] = vault::vault_encrypt(plain, p);
    ASSERT_EQ(enc_err, vault::CryptoError::OK);
    auto [res, dec_err] = vault::vault_decrypt(ct, p.password);
    ASSERT_EQ(dec_err, vault::CryptoError::OK);
    ASSERT_EQ(res.metadata->timestamp_unix, 0ULL);
}

TEST(metadata_max_timestamp) {
    std::vector<uint8_t> plain = {0x01};
    vault::EncryptParams p;
    p.password   = "max-ts";
    p.iterations = vault::KDF_ITER_MIN;
    vault::Metadata m;
    m.original_filename = "a";
    m.timestamp_unix    = UINT64_MAX;
    p.metadata = m;

    auto [ct, enc_err] = vault::vault_encrypt(plain, p);
    ASSERT_EQ(enc_err, vault::CryptoError::OK);
    auto [res, dec_err] = vault::vault_decrypt(ct, p.password);
    ASSERT_EQ(dec_err, vault::CryptoError::OK);
    ASSERT_EQ(res.metadata->timestamp_unix, UINT64_MAX);
}

//
// Header parsing
//

TEST(parse_header_success) {
    std::vector<uint8_t> plain = {0x01};
    auto p = make_params("hdr-pw");
    auto [ct, enc_err] = vault::vault_encrypt(plain, p);
    ASSERT_EQ(enc_err, vault::CryptoError::OK);

    auto [hdr, err] = vault::vault_parse_header(ct);
    ASSERT_EQ(err, vault::CryptoError::OK);
    ASSERT_EQ(hdr.version, vault::FORMAT_VERSION);
    ASSERT_EQ(hdr.algorithm, vault::ALGO_AES256GCM);
    ASSERT_EQ(hdr.kdf_iterations, vault::KDF_ITER_MIN);
}

TEST(parse_header_preserves_iterations) {
    std::vector<uint8_t> plain = {0x01};
    vault::EncryptParams p;
    p.password   = "iter-hdr";
    p.iterations = 200000;

    auto [ct, enc_err] = vault::vault_encrypt(plain, p);
    ASSERT_EQ(enc_err, vault::CryptoError::OK);

    auto [hdr, err] = vault::vault_parse_header(ct);
    ASSERT_EQ(err, vault::CryptoError::OK);
    ASSERT_EQ(hdr.kdf_iterations, 200000u);
}

//
// Encrypt input validation
//

TEST(encrypt_empty_password_rejected) {
    std::vector<uint8_t> plain = {0x01};
    vault::EncryptParams p;
    p.password   = "";
    p.iterations = vault::KDF_ITER_MIN;
    auto [ct, err] = vault::vault_encrypt(plain, p);
    ASSERT_EQ(err, vault::CryptoError::INVALID_INPUT);
}

TEST(encrypt_invalid_iterations_rejected) {
    std::vector<uint8_t> plain = {0x01};
    vault::EncryptParams p;
    p.password   = "pw";
    p.iterations = 1;
    auto [ct, err] = vault::vault_encrypt(plain, p);
    ASSERT_EQ(err, vault::CryptoError::BAD_ITERATIONS);
}

//
// Secure memory
//

TEST(secure_zero_clears_buffer) {
    std::vector<uint8_t> buf(64, 0xFF);
    secure_zero(buf.data(), buf.size());
    for (auto b : buf) ASSERT_EQ(b, 0);
}

TEST(secure_zero_zero_length_safe) {
    uint8_t dummy = 0xAB;
    secure_zero(&dummy, 0); // must not crash
    ASSERT_EQ(dummy, 0xAB); // untouched
}

TEST(secure_zero_null_safe) {
    secure_zero(nullptr, 0); // must not crash
}

//
// Fuzz-style truncation
//

TEST(fuzz_truncated_vault) {
    std::vector<uint8_t> plain = {0x01, 0x02, 0x03};
    auto p = make_params("fuzz-pw");
    auto [ct, enc_err] = vault::vault_encrypt(plain, p);
    ASSERT_EQ(enc_err, vault::CryptoError::OK);

    // Try every possible truncation — none should crash
    for (size_t len = 0; len < ct.size(); ++len) {
        std::vector<uint8_t> trunc(ct.begin(), ct.begin() + len);
        auto [res, err] = vault::vault_decrypt(trunc, p.password);
        // Any error is acceptable; a crash is not
        (void)err;
    }
}

TEST(fuzz_random_bytes) {
    // Feed 200 bytes of pseudo-random data — must not crash
    std::vector<uint8_t> rand_data(200);
    vault::csprng_fill(rand_data.data(), rand_data.size());
    auto [res, err] = vault::vault_decrypt(rand_data, "any-pw");
    (void)err;
}

// Main

int main() {
    std::cout << "=== SecureVault Unit Tests ===\n\n";

    // CSPRNG
    RUN(csprng_returns_success);
    RUN(csprng_produces_nonzero);
    RUN(csprng_two_calls_differ);

    // KDF
    RUN(kdf_success);
    RUN(kdf_deterministic);
    RUN(kdf_different_passwords_differ);
    RUN(kdf_different_salts_differ);
    RUN(kdf_rejects_low_iterations);
    RUN(kdf_rejects_too_high_iterations);

    // Roundtrip
    RUN(roundtrip_basic);
    RUN(roundtrip_empty_plaintext);
    RUN(roundtrip_1kb);
    RUN(roundtrip_binary_data);
    RUN(roundtrip_all_zeros);
    RUN(roundtrip_all_0xFF);
    RUN(encrypt_different_runs_produce_different_ct);

    // Authentication
    RUN(wrong_password_rejected);
    RUN(empty_password_rejected);
    RUN(tamper_ciphertext_body_detected);
    RUN(tamper_tag_detected);
    RUN(tamper_salt_detected);
    RUN(tamper_nonce_detected);

    // Bad header
    RUN(bad_magic_rejected);
    RUN(truncated_blob_rejected);
    RUN(empty_blob_rejected);
    RUN(bad_version_rejected);
    RUN(bad_algorithm_rejected);

    // Metadata
    RUN(metadata_roundtrip);
    RUN(metadata_timestamp_byte_order);
    RUN(no_metadata_flag);
    RUN(metadata_tampering_detected);
    RUN(metadata_long_filename);
    RUN(metadata_zero_timestamp);
    RUN(metadata_max_timestamp);

    // Header parsing
    RUN(parse_header_success);
    RUN(parse_header_preserves_iterations);

    // Encrypt validation
    RUN(encrypt_empty_password_rejected);
    RUN(encrypt_invalid_iterations_rejected);

    // Secure memory
    RUN(secure_zero_clears_buffer);
    RUN(secure_zero_zero_length_safe);
    RUN(secure_zero_null_safe);

    // Fuzz
    RUN(fuzz_truncated_vault);
    RUN(fuzz_random_bytes);

    int total = g_passed + g_failed;
    std::cout << "\n=== Results: " << total << " tests, "
              << g_passed << " passed, " << g_failed << " failed ===\n";

    return (g_failed == 0) ? 0 : 1;
}