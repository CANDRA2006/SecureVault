#pragma once

#include <vector>
#include <string>
#include <cstdint>

std::vector<uint8_t> derive_key(const std::string& password);