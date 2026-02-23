#include "aes.h"

extern "C" void xor_core(uint8_t* data, uint8_t* key, size_t len);

AES256::AES256(const std::vector<uint8_t>& k) : key(k) {}

void AES256::encrypt(std::vector<uint8_t>& data) {
    if (data.empty()) return;

    xor_core(data.data(), key.data(), data.size());
}

void AES256::decrypt(std::vector<uint8_t>& data) {
    if (data.empty()) return;

    xor_core(data.data(), key.data(), data.size());
}