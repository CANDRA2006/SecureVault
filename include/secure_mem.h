#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

// ── Platform-agnostic secure zero ─────────────────────────────────────────
inline void secure_zero(void* ptr, size_t len) noexcept {
#if defined(_WIN32)
    SecureZeroMemory(ptr, len);
#else
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    while (len--) *p++ = 0;
    // Compiler memory barrier to prevent reordering
    __asm__ __volatile__("" ::: "memory");
#endif
}

extern "C" void secure_wipe(uint8_t* data, size_t size);

inline void secure_wipe_compat(uint8_t* data, size_t size) noexcept {
    secure_zero(data, size);
}