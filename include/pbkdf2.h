#pragma once
// Legacy stub — kept for backward compatibility.
// Actual KDF is PBKDF2-HMAC-SHA256 via OpenSSL in crypto_engine.cpp.
#include <vector>
#include <string>
#include <cstdint>

inline std::vector<uint8_t> derive_key(const std::string& /*password*/) {
    return std::vector<uint8_t>(32, 0);
}