/**
 * benchmark.cpp — SecureVault performance benchmarks
 *
 * Measures:
 *   1. KDF (PBKDF2) time at various iteration counts
 *   2. AES-256-GCM encrypt/decrypt throughput
 *   3. Metadata overhead
 */

#include "crypto_engine.h"

#include <iostream>
#include <chrono>
#include <iomanip>
#include <vector>
#include <cstdint>

using Clock = std::chrono::steady_clock;
using Ms    = std::chrono::milliseconds;
using Us    = std::chrono::microseconds;

static double elapsed_ms(Clock::time_point t0, Clock::time_point t1) {
    return static_cast<double>(
        std::chrono::duration_cast<Us>(t1 - t0).count()) / 1000.0;
}

void benchmark_kdf() {
    std::cout << "\n=== KDF Benchmark (PBKDF2-HMAC-SHA256) ===\n";
    std::cout << std::left << std::setw(15) << "Iterations"
              << std::setw(15) << "Time (ms)" << '\n';
    std::cout << std::string(30, '-') << '\n';

    uint8_t salt[32]{};
    vault::csprng_fill(salt, 32);

    for (uint32_t iters : {100000u, 300000u, 600000u, 1000000u}) {
        vault::SecureKey key(vault::KEY_LEN);
        auto t0 = Clock::now();
        vault::pbkdf2_derive("benchmark-password", salt, 32, iters, key);
        auto t1 = Clock::now();
        std::cout << std::left << std::setw(15) << iters
                  << std::setw(15) << std::fixed << std::setprecision(1)
                  << elapsed_ms(t0, t1) << '\n';
    }
}

void benchmark_throughput() {
    std::cout << "\n=== AES-256-GCM Throughput ===\n";
    std::cout << std::left << std::setw(15) << "Size"
              << std::setw(20) << "Enc (MB/s)"
              << std::setw(20) << "Dec (MB/s)" << '\n';
    std::cout << std::string(55, '-') << '\n';

    vault::EncryptParams p;
    p.password   = "throughput-test";
    p.iterations = vault::KDF_ITER_MIN; // minimize KDF overhead in throughput test

    for (size_t size : {1024ul, 65536ul, 1048576ul, 10485760ul}) {
        std::vector<uint8_t> plain(size, 0xAB);

        auto t0 = Clock::now();
        auto [ct, enc_err] = vault::vault_encrypt(plain, p);
        auto t1 = Clock::now();

        double enc_ms = elapsed_ms(t0, t1);
        double enc_mb_s = (enc_err == vault::CryptoError::OK)
                          ? (static_cast<double>(size) / 1048576.0) / (enc_ms / 1000.0)
                          : 0.0;

        double dec_mb_s = 0.0;
        if (enc_err == vault::CryptoError::OK) {
            auto t2 = Clock::now();
            auto [res, dec_err] = vault::vault_decrypt(ct, p.password);
            auto t3 = Clock::now();
            double dec_ms = elapsed_ms(t2, t3);
            dec_mb_s = (dec_err == vault::CryptoError::OK)
                       ? (static_cast<double>(size) / 1048576.0) / (dec_ms / 1000.0)
                       : 0.0;
        }

        // Format size
        std::string size_str;
        if (size < 1024) size_str = std::to_string(size) + " B";
        else if (size < 1048576) size_str = std::to_string(size/1024) + " KB";
        else size_str = std::to_string(size/1048576) + " MB";

        std::cout << std::left << std::setw(15) << size_str
                  << std::setw(20) << std::fixed << std::setprecision(1) << enc_mb_s
                  << std::setw(20) << dec_mb_s << '\n';
    }
}

void benchmark_metadata_overhead() {
    std::cout << "\n=== Metadata Overhead ===\n";
    std::vector<uint8_t> plain(4096, 0x42);
    vault::EncryptParams p;
    p.password   = "meta-overhead-test";
    p.iterations = vault::KDF_ITER_MIN;

    // Without metadata
    auto t0 = Clock::now();
    auto [ct_no, e1] = vault::vault_encrypt(plain, p);
    auto t1 = Clock::now();

    // With metadata
    vault::Metadata m;
    m.original_filename = "some_long_filename_document.pdf";
    m.timestamp_unix    = 1700000000ULL;
    p.metadata = m;
    auto t2 = Clock::now();
    auto [ct_meta, e2] = vault::vault_encrypt(plain, p);
    auto t3 = Clock::now();

    std::cout << "Without metadata: "
              << std::fixed << std::setprecision(2) << elapsed_ms(t0, t1)
              << " ms, " << ct_no.size() << " bytes\n";
    std::cout << "With metadata:    "
              << elapsed_ms(t2, t3)
              << " ms, " << ct_meta.size() << " bytes\n";
    if (!ct_no.empty() && !ct_meta.empty()) {
        std::cout << "Overhead: " << (ct_meta.size() - ct_no.size()) << " bytes\n";
    }
}

// Legacy benchmark function (backward compat)
void benchmark() {
    std::cout << "=== SecureVault Benchmark Suite ===\n";
    benchmark_kdf();
    benchmark_throughput();
    benchmark_metadata_overhead();
    std::cout << "\nBenchmark complete\n";
}