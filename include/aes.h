#pragma once
#include <vector>
#include <cstdint>

class AES256 {
public:
    AES256(const std::vector<uint8_t>& key);
    void encrypt(std::vector<uint8_t>& data);
    void decrypt(std::vector<uint8_t>& data);

private:
    std::vector<uint8_t> key;
};