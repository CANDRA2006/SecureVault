#ifndef SECURE_MEMORY_H
#define SECURE_MEMORY_H

#include <cstddef>
#include <cstdint>

extern "C" void secure_wipe(uint8_t* data, size_t size);

#endif