/**
 * file_io.cpp — Atomic write via temp-file + fsync + rename.
 *
 * POSIX: uses fdatasync() + rename() (atomic on same filesystem).
 * Windows: uses FlushFileBuffers() + MoveFileExA(MOVEFILE_REPLACE_EXISTING).
 */

#include "file_io.h"

#include <fstream>
#include <cstdio>
#include <cerrno>
#include <cstring>

#if defined(_WIN32)
    #include <windows.h>
#else
    #include <unistd.h>
    #include <fcntl.h>
    #include <sys/stat.h>
#endif

namespace vault {

std::vector<uint8_t> read_file(const std::string& path, IOError& err) noexcept {
    err = IOError::OK;
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f.is_open()) { err = IOError::READ_FAILED; return {}; }

    auto size = f.tellg();
    if (size < 0) { err = IOError::READ_FAILED; return {}; }
    f.seekg(0);

    std::vector<uint8_t> buf(static_cast<size_t>(size));
    if (!f.read(reinterpret_cast<char*>(buf.data()), size)) {
        err = IOError::READ_FAILED;
        return {};
    }
    return buf;
}

IOError atomic_write_file(const std::string& path,
                           const std::vector<uint8_t>& data) noexcept {
    std::string tmp_path = path + ".svtmp";

#if defined(_WIN32)
    // Windows path
    HANDLE h = CreateFileA(tmp_path.c_str(),
                            GENERIC_WRITE, 0, nullptr,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return IOError::TEMP_FAILED;

    DWORD written = 0;
    bool ok = WriteFile(h, data.data(), static_cast<DWORD>(data.size()),
                        &written, nullptr) && (written == data.size());
    if (ok) ok = FlushFileBuffers(h);
    CloseHandle(h);

    if (!ok) { DeleteFileA(tmp_path.c_str()); return IOError::WRITE_FAILED; }

    if (!MoveFileExA(tmp_path.c_str(), path.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileA(tmp_path.c_str());
        return IOError::WRITE_FAILED;
    }
#else
    // POSIX path
    int fd = ::open(tmp_path.c_str(),
                    O_WRONLY | O_CREAT | O_TRUNC,
                    S_IRUSR | S_IWUSR); // 0600: owner only
    if (fd < 0) return IOError::TEMP_FAILED;

    size_t written = 0;
    while (written < data.size()) {
        ssize_t n = ::write(fd, data.data() + written, data.size() - written);
        if (n <= 0) {
            ::close(fd);
            ::unlink(tmp_path.c_str());
            return IOError::WRITE_FAILED;
        }
        written += static_cast<size_t>(n);
    }

    if (::fdatasync(fd) != 0) {
        ::close(fd);
        ::unlink(tmp_path.c_str());
        return IOError::WRITE_FAILED;
    }
    ::close(fd);

    if (::rename(tmp_path.c_str(), path.c_str()) != 0) {
        ::unlink(tmp_path.c_str());
        return IOError::WRITE_FAILED;
    }
#endif

    return IOError::OK;
}

} // namespace vault