#ifndef HMAC_H
#define HMAC_H

#include <vector>
#include <cstdint>

std::vector<uint8_t> hmac_sha256(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& message
);

#endif