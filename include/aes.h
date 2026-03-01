#pragma once
// Legacy stub — kept for backward compatibility.
// Actual AES-256-GCM is implemented via OpenSSL EVP in crypto_engine.cpp.
#include <vector>
#include <cstdint>

class AES256 {
public:
    explicit AES256(const std::vector<uint8_t>& key) : key_(key) {}
    void encrypt(std::vector<uint8_t>& /*data*/) {}
    void decrypt(std::vector<uint8_t>& /*data*/) {}
private:
    std::vector<uint8_t> key_;
};