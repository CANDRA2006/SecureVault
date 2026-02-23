#include "pbkdf2.h"

std::vector<uint8_t> derive_key(const std::string& password) {
    std::vector<uint8_t> key(32, 0);

    for (size_t i = 0; i < password.size(); ++i) {
        key[i % 32] ^= static_cast<uint8_t>(password[i]);
        key[(i * 7) % 32] ^= static_cast<uint8_t>(password[i] * 3);
    }

    return key;
}