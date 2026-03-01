#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>
#include <string>

// ── Platform-agnostic secure zero ─────────────────────────────────────────
inline void secure_zero(void* ptr, size_t len) noexcept {
    if (!ptr || len == 0) return;
#if defined(_WIN32)
    SecureZeroMemory(ptr, len);
#else
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    size_t remaining = len;
    while (remaining--) *p++ = 0;
    // Compiler memory barrier to prevent reordering / optimization removal
    __asm__ __volatile__("" ::: "memory");
#endif
}

// ── Convenience overloads ─────────────────────────────────────────────────
inline void secure_zero(std::vector<uint8_t>& v) noexcept {
    secure_zero(v.data(), v.size());
}

inline void secure_zero(std::string& s) noexcept {
    if (!s.empty()) secure_zero(s.data(), s.size());
}

// ── RAII guard: auto-zeroize a plaintext buffer on scope exit ─────────────
// Use this to guarantee zeroization on ALL exit paths (normal, early return,
// exception) without manually tracking every code path.
//
// Usage:
//   auto [result, err] = vault_decrypt(...);
//   PlaintextGuard guard(result.plaintext);  // wipes on any exit
//   if (err != OK) return EXIT_CRYPTO;       // guard fires here too
//
struct PlaintextGuard {
    std::vector<uint8_t>& data;
    explicit PlaintextGuard(std::vector<uint8_t>& d) noexcept : data(d) {}
    ~PlaintextGuard() noexcept { secure_zero(data.data(), data.size()); }

    PlaintextGuard(const PlaintextGuard&)            = delete;
    PlaintextGuard& operator=(const PlaintextGuard&) = delete;
};

// ── RAII guard: auto-zeroize a std::string on scope exit ─────────────────
struct PasswordGuard {
    std::string& pw;
    explicit PasswordGuard(std::string& p) noexcept : pw(p) {}
    ~PasswordGuard() noexcept { secure_zero(pw); }

    PasswordGuard(const PasswordGuard&)            = delete;
    PasswordGuard& operator=(const PasswordGuard&) = delete;
};

// ── ASM-backed wipe (defined in src/asm/secure_wipe.asm) ─────────────────
extern "C" void secure_wipe(uint8_t* data, size_t size);

inline void secure_wipe_compat(uint8_t* data, size_t size) noexcept {
    secure_zero(data, size);
}