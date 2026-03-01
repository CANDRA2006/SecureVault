#pragma once

#include <vector>
#include <string>
#include <cstdint>

namespace vault {

enum class IOError { OK, READ_FAILED, WRITE_FAILED, TEMP_FAILED };

/// Read entire file into memory. Returns empty vector on error.
/// Enforces MAX_FILE_SIZE limit (defined in vault_format.h).
std::vector<uint8_t> read_file(const std::string& path, IOError& err) noexcept;

/**
 * Write data to path using atomic strategy:
 *   1. Write to <path>.tmp
 *   2. fsync the file
 *   3. rename <path>.tmp → <path>
 * This ensures the target file is never partially written on crash.
 */
IOError atomic_write_file(const std::string& path,
                           const std::vector<uint8_t>& data) noexcept;

} // namespace vault