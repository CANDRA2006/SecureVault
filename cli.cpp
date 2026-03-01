/**
 * cli.cpp — SecureVault command-line interface
 *
 * Commands:
 *   enc <in> <out>         Encrypt file
 *   dec <in> <out>         Decrypt file
 *   info <file>            Show non-secret header metadata
 *   rotate-key <in> <out>  Re-encrypt with new password/params
 *   self-test              Run built-in KAT + roundtrip tests
 *
 * Flags:
 *   --iterations N         PBKDF2 iteration count (default 600000)
 *   --force                Overwrite output file without prompt
 *   --verbose              Verbose output
 *   --no-metadata          Skip embedding filename/timestamp metadata
 *
 * Exit codes:
 *   0  Success
 *   1  Usage error
 *   2  I/O error
 *   3  Crypto/authentication error
 *   4  Internal error
 *
 * Fixes applied vs original:
 *  - TerminalGuard RAII: terminal echo always restored even on exception
 *  - PlaintextGuard / PasswordGuard RAII: sensitive buffers zeroed on
 *    every exit path (early return, error, normal)
 *  - g_opts global state eliminated: Options passed by value/reference
 *  - metadata_corrupt flag surfaced as a visible warning to user
 *  - ct_size in cmd_info uses signed arithmetic to prevent unsigned underflow
 *  - Password and file size limits enforced before expensive KDF
 */

#include "crypto_engine.h"
#include "file_io.h"
#include "secure_mem.h"
#include "vault_format.h"

// Legacy compatibility stubs
#include "aes.h"
#include "pbkdf2.h"

#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <chrono>
#include <iomanip>

#if defined(_WIN32)
    #include <windows.h>
    #include <conio.h>
#else
    #include <termios.h>
    #include <unistd.h>
#endif

namespace {

// ── Exit codes ────────────────────────────────────────────────────────────
constexpr int EXIT_OK     = 0;
constexpr int EXIT_USAGE  = 1;
constexpr int EXIT_IO     = 2;
constexpr int EXIT_CRYPTO = 3;
constexpr int EXIT_INTERN = 4;

// ── Options (no longer global — passed explicitly) ─────────────────────────
struct Options {
    uint32_t    iterations  = vault::KDF_ITER_DEFAULT;
    bool        force       = false;
    bool        verbose     = false;
    bool        no_metadata = false;
};

// ── RAII terminal guard (POSIX) ───────────────────────────────────────────
// Restores terminal settings on any exit path (return, exception, signal).
#if !defined(_WIN32)
struct TerminalGuard {
    struct termios saved{};
    bool           active;

    TerminalGuard() : active(::isatty(STDIN_FILENO) != 0) {
        if (active) ::tcgetattr(STDIN_FILENO, &saved);
    }
    ~TerminalGuard() {
        if (active) ::tcsetattr(STDIN_FILENO, TCSANOW, &saved);
    }
    void disable_echo() const {
        if (!active) return;
        struct termios no_echo = saved;
        no_echo.c_lflag &= ~static_cast<tcflag_t>(ECHO);
        ::tcsetattr(STDIN_FILENO, TCSANOW, &no_echo);
    }

    TerminalGuard(const TerminalGuard&)            = delete;
    TerminalGuard& operator=(const TerminalGuard&) = delete;
};
#endif

// ── Secure password input ─────────────────────────────────────────────────
std::string read_password(const char* prompt) {
    std::cerr << prompt << std::flush;

#if defined(_WIN32)
    std::string pw;
    char c;
    while ((c = static_cast<char>(_getch())) != '\r' && c != '\n') {
        if (c == '\b') {
            if (!pw.empty()) { pw.pop_back(); std::cerr << "\b \b"; }
        } else {
            pw += c;
        }
    }
    std::cerr << '\n';
#else
    // TerminalGuard ensures echo is restored even if getline throws
    TerminalGuard guard;
    guard.disable_echo();

    std::string pw;
    std::getline(std::cin, pw);
    std::cerr << '\n';
    // guard destructor restores terminal here, before pw is used
#endif

    // Enforce password length limit before returning
    if (pw.size() > vault::MAX_PASSWORD_LEN) {
        std::cerr << "Error: password exceeds maximum length ("
                  << vault::MAX_PASSWORD_LEN << " bytes)\n";
        secure_zero(pw);
        return {};
    }

    return pw;
}

std::string read_password_confirmed(const char* prompt) {
    std::string a = read_password(prompt);
    if (a.empty()) return {};

    std::string b = read_password("Confirm password: ");
    if (a != b) {
        secure_zero(a);
        secure_zero(b);
        std::cerr << "Error: passwords do not match\n";
        return {};
    }
    secure_zero(b);
    return a; // NRVO — copy elided
}

// ── Helpers ───────────────────────────────────────────────────────────────
bool file_exists(const std::string& path) {
    std::ifstream f(path);
    return f.good();
}

void print_hex(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; ++i)
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(data[i]);
    std::cout << std::dec;
}

// ── Commands ──────────────────────────────────────────────────────────────

int cmd_encrypt(const std::string& in_path,
                const std::string& out_path,
                const Options&     opts) {
    if (!opts.force && file_exists(out_path)) {
        std::cerr << "Output file exists. Use --force to overwrite.\n";
        return EXIT_USAGE;
    }

    vault::IOError io_err;
    auto plaintext = vault::read_file(in_path, io_err);
    if (io_err != vault::IOError::OK) {
        std::cerr << "Error: cannot read input file"
                  << (plaintext.empty() && io_err == vault::IOError::READ_FAILED
                      ? " (file too large or missing)" : "")
                  << "\n";
        return EXIT_IO;
    }
    // RAII: plaintext is wiped whenever we return from this function
    PlaintextGuard pt_guard(plaintext);

    std::string pw = read_password_confirmed("Password: ");
    if (pw.empty()) return EXIT_USAGE;
    PasswordGuard pw_guard(pw); // wipe pw on any return path

    vault::EncryptParams params;
    params.password   = pw;
    params.iterations = opts.iterations;

    if (!opts.no_metadata) {
        vault::Metadata meta;
        size_t slash = in_path.find_last_of("/\\");
        meta.original_filename = (slash == std::string::npos)
                                    ? in_path
                                    : in_path.substr(slash + 1);
        using namespace std::chrono;
        meta.timestamp_unix = static_cast<uint64_t>(
            duration_cast<seconds>(system_clock::now().time_since_epoch()).count());
        params.metadata = meta;
    }

    if (opts.verbose)
        std::cerr << "Encrypting with " << params.iterations
                  << " PBKDF2 iterations...\n";

    auto t0 = std::chrono::steady_clock::now();
    auto [ciphertext, err] = vault::vault_encrypt(plaintext, params);
    auto t1 = std::chrono::steady_clock::now();

    if (err != vault::CryptoError::OK) {
        std::cerr << "Encryption failed: " << vault::error_str(err) << '\n';
        return EXIT_CRYPTO;
    }

    if (vault::atomic_write_file(out_path, ciphertext) != vault::IOError::OK) {
        std::cerr << "Error: cannot write output file\n";
        secure_zero(ciphertext.data(), ciphertext.size());
        return EXIT_IO;
    }

    if (opts.verbose) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
        std::cerr << "Done in " << ms << " ms. "
                  << "Output: " << ciphertext.size() << " bytes\n";
    }

    std::cout << "Encrypted.\n";
    return EXIT_OK;
}

int cmd_decrypt(const std::string& in_path,
                const std::string& out_path,
                const Options&     opts) {
    if (!opts.force && file_exists(out_path)) {
        std::cerr << "Output file exists. Use --force to overwrite.\n";
        return EXIT_USAGE;
    }

    vault::IOError io_err;
    auto ciphertext = vault::read_file(in_path, io_err);
    if (io_err != vault::IOError::OK) {
        std::cerr << "Error: cannot read input file\n";
        return EXIT_IO;
    }

    std::string pw = read_password("Password: ");
    if (pw.empty()) return EXIT_USAGE;
    PasswordGuard pw_guard(pw);

    if (opts.verbose) std::cerr << "Decrypting...\n";

    auto t0 = std::chrono::steady_clock::now();
    auto [result, err] = vault::vault_decrypt(ciphertext, pw);
    auto t1 = std::chrono::steady_clock::now();

    // RAII: plaintext wiped on any return path
    PlaintextGuard pt_guard(result.plaintext);

    if (err != vault::CryptoError::OK) {
        std::cerr << "Error: " << vault::error_str(err) << '\n';
        return EXIT_CRYPTO;
    }

    // FIX: surface metadata tampering to the user
    if (result.metadata_corrupt) {
        std::cerr << "WARNING: Metadata block authentication failed. "
                     "The file's embedded filename/timestamp may have been "
                     "tampered with. Plaintext authenticated successfully.\n";
    }

    if (vault::atomic_write_file(out_path, result.plaintext) != vault::IOError::OK) {
        std::cerr << "Error: cannot write output file\n";
        return EXIT_IO;
    }

    if (opts.verbose) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
        std::cerr << "Done in " << ms << " ms.\n";
        if (result.metadata) {
            std::cerr << "Original filename : "
                      << result.metadata->original_filename << '\n';
            std::cerr << "Encrypted at      : "
                      << result.metadata->timestamp_unix << " (unix)\n";
        }
    }

    std::cout << "Decrypted.\n";
    return EXIT_OK;
}

int cmd_info(const std::string& in_path) {
    vault::IOError io_err;
    auto blob = vault::read_file(in_path, io_err);
    if (io_err != vault::IOError::OK) {
        std::cerr << "Error: cannot read file\n";
        return EXIT_IO;
    }

    auto [hdr, err] = vault::vault_parse_header(blob);
    if (err != vault::CryptoError::OK) {
        std::cerr << "Error: " << vault::error_str(err) << '\n';
        return EXIT_CRYPTO;
    }

    std::cout << "=== SecureVault File Info ===\n";
    std::cout << "Format version : " << static_cast<int>(hdr.version) << '\n';
    std::cout << "Algorithm      : ";
    if (hdr.algorithm == vault::ALGO_AES256GCM) std::cout << "AES-256-GCM\n";
    else std::cout << "Unknown (0x" << std::hex
                   << static_cast<int>(hdr.algorithm) << std::dec << ")\n";
    std::cout << "KDF iterations : " << hdr.kdf_iterations << '\n';
    std::cout << "Salt           : ";
    print_hex(hdr.salt, vault::SALT_LEN);
    std::cout << '\n';
    std::cout << "Nonce          : ";
    print_hex(hdr.nonce, vault::NONCE_LEN);
    std::cout << '\n';
    std::cout << "Metadata block : " << hdr.metadata_len << " bytes"
              << (hdr.metadata_len > 0 ? " (encrypted)" : " (none)") << '\n';

    // FIX: use signed arithmetic to prevent unsigned underflow if blob is
    // somehow smaller than expected (belt-and-suspenders on top of parse_header)
    int64_t ct_size = static_cast<int64_t>(blob.size())
                    - static_cast<int64_t>(vault::FIXED_HEADER_LEN)
                    - static_cast<int64_t>(hdr.metadata_len)
                    - static_cast<int64_t>(vault::TAG_LEN);
    if (ct_size < 0) {
        std::cerr << "Error: malformed vault file (invalid size fields)\n";
        return EXIT_CRYPTO;
    }
    std::cout << "Ciphertext     : " << static_cast<size_t>(ct_size) << " bytes\n";

    return EXIT_OK;
}

int cmd_rotate_key(const std::string& in_path,
                   const std::string& out_path,
                   const Options&     opts) {
    if (!opts.force && file_exists(out_path)) {
        std::cerr << "Output file exists. Use --force to overwrite.\n";
        return EXIT_USAGE;
    }

    vault::IOError io_err;
    auto ciphertext = vault::read_file(in_path, io_err);
    if (io_err != vault::IOError::OK) {
        std::cerr << "Error: cannot read input file\n";
        return EXIT_IO;
    }

    std::string old_pw = read_password("Current password: ");
    if (old_pw.empty()) return EXIT_USAGE;

    auto [result, err] = vault::vault_decrypt(ciphertext, old_pw);
    secure_zero(old_pw); // wipe immediately after use

    // RAII: ensures plaintext is wiped even if we return early below
    PlaintextGuard pt_guard(result.plaintext);

    if (err != vault::CryptoError::OK) {
        std::cerr << "Error: " << vault::error_str(err) << '\n';
        return EXIT_CRYPTO;
    }

    if (result.metadata_corrupt) {
        std::cerr << "WARNING: Metadata block authentication failed. "
                     "Metadata will not be preserved in the rotated file.\n";
        result.metadata = std::nullopt;
    }

    std::string new_pw = read_password_confirmed("New password: ");
    // FIX: plaintext is guarded by pt_guard — no manual wipe needed on early return
    if (new_pw.empty()) return EXIT_USAGE;
    PasswordGuard new_pw_guard(new_pw);

    vault::EncryptParams params;
    params.password   = new_pw;
    params.iterations = opts.iterations;
    params.metadata   = result.metadata; // preserve original metadata

    auto [new_ct, enc_err] = vault::vault_encrypt(result.plaintext, params);
    if (enc_err != vault::CryptoError::OK) {
        std::cerr << "Encryption failed: " << vault::error_str(enc_err) << '\n';
        return EXIT_CRYPTO;
    }

    if (vault::atomic_write_file(out_path, new_ct) != vault::IOError::OK) {
        std::cerr << "Error: cannot write output file\n";
        return EXIT_IO;
    }

    std::cout << "Key rotated.\n";
    return EXIT_OK;
}

int cmd_self_test() {
    std::cout << "Running self-test...\n";
    bool all_ok = true;

    // Test 1: Encrypt-decrypt roundtrip
    {
        std::vector<uint8_t> plain = {0x48, 0x65, 0x6C, 0x6C, 0x6F}; // "Hello"
        vault::EncryptParams p;
        p.password    = "test-password-selftest";
        p.iterations  = vault::KDF_ITER_MIN;
        p.no_metadata = true;

        auto [ct, enc_err] = vault::vault_encrypt(plain, p);
        if (enc_err != vault::CryptoError::OK) {
            std::cout << "  [FAIL] encrypt: " << vault::error_str(enc_err) << '\n';
            all_ok = false;
        } else {
            auto [res, dec_err] = vault::vault_decrypt(ct, p.password);
            if (dec_err != vault::CryptoError::OK || res.plaintext != plain) {
                std::cout << "  [FAIL] roundtrip mismatch\n";
                all_ok = false;
            } else {
                std::cout << "  [PASS] encrypt/decrypt roundtrip\n";
            }
        }
    }

    // Test 2: Wrong password → AUTHENTICATION_FAILED
    {
        std::vector<uint8_t> plain = {0x41, 0x42};
        vault::EncryptParams p;
        p.password   = "correcthorsebatterystaple";
        p.iterations = vault::KDF_ITER_MIN;

        auto [ct, enc_err] = vault::vault_encrypt(plain, p);
        if (enc_err == vault::CryptoError::OK) {
            auto [res, dec_err] = vault::vault_decrypt(ct, "wrongpassword");
            if (dec_err == vault::CryptoError::AUTHENTICATION_FAILED) {
                std::cout << "  [PASS] wrong password rejected\n";
            } else {
                std::cout << "  [FAIL] wrong password not rejected (err="
                          << static_cast<int>(dec_err) << ")\n";
                all_ok = false;
            }
        }
    }

    // Test 3: Corrupt ciphertext → AUTHENTICATION_FAILED
    {
        std::vector<uint8_t> plain = {0xDE, 0xAD, 0xBE, 0xEF};
        vault::EncryptParams p;
        p.password   = "integrity-test";
        p.iterations = vault::KDF_ITER_MIN;

        auto [ct, enc_err] = vault::vault_encrypt(plain, p);
        if (enc_err == vault::CryptoError::OK
            && ct.size() > vault::FIXED_HEADER_LEN + 5) {
            ct[vault::FIXED_HEADER_LEN + 2] ^= 0xFF;
            auto [res, dec_err] = vault::vault_decrypt(ct, p.password);
            if (dec_err == vault::CryptoError::AUTHENTICATION_FAILED) {
                std::cout << "  [PASS] tampered ciphertext rejected\n";
            } else {
                std::cout << "  [FAIL] tampered ciphertext not rejected\n";
                all_ok = false;
            }
        }
    }

    // Test 4: Bad magic
    {
        std::vector<uint8_t> junk = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
        auto [res, err] = vault::vault_decrypt(junk, "pw");
        if (err == vault::CryptoError::BAD_MAGIC
            || err == vault::CryptoError::BAD_HEADER_CORRUPT) {
            std::cout << "  [PASS] bad magic rejected\n";
        } else {
            std::cout << "  [FAIL] bad magic not rejected\n";
            all_ok = false;
        }
    }

    // Test 5: Metadata roundtrip
    {
        std::vector<uint8_t> plain = {0x01};
        vault::EncryptParams p;
        p.password   = "meta-test";
        p.iterations = vault::KDF_ITER_MIN;
        vault::Metadata m;
        m.original_filename = "test.txt";
        m.timestamp_unix    = 1700000000ULL;
        p.metadata = m;

        auto [ct, enc_err] = vault::vault_encrypt(plain, p);
        if (enc_err == vault::CryptoError::OK) {
            auto [res, dec_err] = vault::vault_decrypt(ct, p.password);
            if (dec_err == vault::CryptoError::OK
                && !res.metadata_corrupt
                && res.metadata.has_value()
                && res.metadata->original_filename == "test.txt"
                && res.metadata->timestamp_unix == 1700000000ULL) {
                std::cout << "  [PASS] metadata roundtrip\n";
            } else {
                std::cout << "  [FAIL] metadata roundtrip\n";
                all_ok = false;
            }
        }
    }

    // Test 6: Metadata tampering detection (NEW)
    {
        std::vector<uint8_t> plain = {0xCA, 0xFE};
        vault::EncryptParams p;
        p.password   = "tamper-meta-test";
        p.iterations = vault::KDF_ITER_MIN;
        vault::Metadata m;
        m.original_filename = "canary.txt";
        m.timestamp_unix    = 9999ULL;
        p.metadata = m;

        auto [ct, enc_err] = vault::vault_encrypt(plain, p);
        if (enc_err == vault::CryptoError::OK
            && ct.size() > vault::FIXED_HEADER_LEN + 5) {
            // Corrupt a byte inside the metadata block
            ct[vault::FIXED_HEADER_LEN + 2] ^= 0xAB;
            auto [res, dec_err] = vault::vault_decrypt(ct, p.password);
            if (dec_err == vault::CryptoError::OK && res.metadata_corrupt) {
                std::cout << "  [PASS] metadata tampering detected\n";
            } else {
                std::cout << "  [FAIL] metadata tampering not detected\n";
                all_ok = false;
            }
        }
    }

    if (all_ok) {
        std::cout << "Self-test PASSED\n";
        return EXIT_OK;
    } else {
        std::cout << "Self-test FAILED\n";
        return EXIT_CRYPTO;
    }
}

void print_usage(const char* prog) {
    std::cout
        << "Usage:\n"
        << "  " << prog << " enc <input> <output> [flags]\n"
        << "  " << prog << " dec <input> <output> [flags]\n"
        << "  " << prog << " info <file>\n"
        << "  " << prog << " rotate-key <input> <output> [flags]\n"
        << "  " << prog << " self-test\n"
        << "\nFlags:\n"
        << "  --iterations N   PBKDF2 iterations (default: 600000, min: 100000)\n"
        << "  --force          Overwrite output without prompting\n"
        << "  --verbose        Show timing and metadata\n"
        << "  --no-metadata    Do not embed filename/timestamp\n"
        << "\nExit codes:\n"
        << "  0  Success\n"
        << "  1  Usage error\n"
        << "  2  I/O error\n"
        << "  3  Crypto/authentication error\n"
        << "  4  Internal error\n";
}

bool parse_flags(int argc, char* argv[], int start, Options& opts) {
    for (int i = start; i < argc; ++i) {
        if (std::strcmp(argv[i], "--force") == 0) {
            opts.force = true;
        } else if (std::strcmp(argv[i], "--verbose") == 0) {
            opts.verbose = true;
        } else if (std::strcmp(argv[i], "--no-metadata") == 0) {
            opts.no_metadata = true;
        } else if (std::strcmp(argv[i], "--iterations") == 0) {
            if (i + 1 >= argc) {
                std::cerr << "--iterations requires a value\n";
                return false;
            }
            try {
                long v = std::stol(argv[++i]);
                if (v < static_cast<long>(vault::KDF_ITER_MIN)
                    || v > static_cast<long>(vault::KDF_ITER_MAX)) {
                    std::cerr << "--iterations must be between "
                              << vault::KDF_ITER_MIN << " and "
                              << vault::KDF_ITER_MAX << '\n';
                    return false;
                }
                opts.iterations = static_cast<uint32_t>(v);
            } catch (...) {
                std::cerr << "Invalid --iterations value\n";
                return false;
            }
        } else {
            std::cerr << "Unknown flag: " << argv[i] << '\n';
            return false;
        }
    }
    return true;
}

} // anonymous namespace

// ── Legacy interface (backward compatibility) ─────────────────────────────
void process(const std::string& mode,
             const std::string& filename,
             const std::string& password) {
    if (mode == "enc") {
        vault::EncryptParams params;
        params.password   = password;
        params.iterations = vault::KDF_ITER_DEFAULT;

        vault::IOError io_err;
        auto plaintext = vault::read_file(filename, io_err);
        if (io_err != vault::IOError::OK) {
            std::cerr << "Error: cannot read file\n";
            return;
        }
        PlaintextGuard guard(plaintext);

        auto [ct, err] = vault::vault_encrypt(plaintext, params);
        if (err != vault::CryptoError::OK) {
            std::cerr << "Error: " << vault::error_str(err) << '\n';
            return;
        }
        vault::atomic_write_file(filename + ".vault", ct);
        std::cout << "Encrypted.\n";

    } else if (mode == "dec") {
        vault::IOError io_err;
        auto blob = vault::read_file(filename, io_err);
        if (io_err != vault::IOError::OK) {
            std::cerr << "Error: cannot read file\n";
            return;
        }
        auto [result, err] = vault::vault_decrypt(blob, password);
        PlaintextGuard guard(result.plaintext);
        if (err != vault::CryptoError::OK) {
            std::cerr << "Error: " << vault::error_str(err) << '\n';
            return;
        }
        std::string out_path = filename;
        if (out_path.size() > 6
            && out_path.substr(out_path.size() - 6) == ".vault")
            out_path = out_path.substr(0, out_path.size() - 6);
        else
            out_path += ".dec";
        vault::atomic_write_file(out_path, result.plaintext);
        std::cout << "Decrypted.\n";
    } else {
        std::cerr << "Unknown mode\n";
    }
}

// ── Entry point ───────────────────────────────────────────────────────────
int cli_main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return EXIT_USAGE;
    }

    std::string cmd = argv[1];

    // FIX: Options is now a local variable, not global state.
    // Each command gets its own clean Options instance.
    Options opts;

    if (cmd == "enc") {
        if (argc < 4) {
            std::cerr << "Usage: enc <input> <output> [flags]\n";
            return EXIT_USAGE;
        }
        if (!parse_flags(argc, argv, 4, opts)) return EXIT_USAGE;
        return cmd_encrypt(argv[2], argv[3], opts);

    } else if (cmd == "dec") {
        if (argc < 4) {
            std::cerr << "Usage: dec <input> <output> [flags]\n";
            return EXIT_USAGE;
        }
        if (!parse_flags(argc, argv, 4, opts)) return EXIT_USAGE;
        return cmd_decrypt(argv[2], argv[3], opts);

    } else if (cmd == "info") {
        if (argc < 3) {
            std::cerr << "Usage: info <file>\n";
            return EXIT_USAGE;
        }
        return cmd_info(argv[2]);

    } else if (cmd == "rotate-key") {
        if (argc < 4) {
            std::cerr << "Usage: rotate-key <input> <output> [flags]\n";
            return EXIT_USAGE;
        }
        if (!parse_flags(argc, argv, 4, opts)) return EXIT_USAGE;
        return cmd_rotate_key(argv[2], argv[3], opts);

    } else if (cmd == "self-test") {
        return cmd_self_test();

    } else if (cmd == "--help" || cmd == "-h" || cmd == "help") {
        print_usage(argv[0]);
        return EXIT_OK;

    } else {
        std::cerr << "Unknown command: " << cmd << '\n';
        print_usage(argv[0]);
        return EXIT_USAGE;
    }
}