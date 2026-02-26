cmake_minimum_required(VERSION 3.15)
project(SecureVault VERSION 2.0.0 LANGUAGES CXX ASM_NASM)

# ── C++ standard ───────────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ── Compiler warnings ──────────────────────────────────────────────────────
if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic -Wno-unused-parameter)
elseif (MSVC)
    add_compile_options(/W4)
endif()

# ── OpenSSL ────────────────────────────────────────────────────────────────
find_package(OpenSSL REQUIRED)

# ── Shared crypto library ──────────────────────────────────────────────────
# Compiled once, linked by main binary + tests + benchmark
set(CRYPTO_SOURCES
    src/crypto/crypto_engine.cpp
    src/file_io.cpp
    src/benchmark.cpp
    src/attack_simulation.cpp
)

add_library(vault_crypto STATIC ${CRYPTO_SOURCES})

target_include_directories(vault_crypto PUBLIC include)

target_link_libraries(vault_crypto PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
)

# ── Assembly objects ───────────────────────────────────────────────────────
if (CMAKE_ASM_NASM_COMPILER)
    # Detect platform for NASM format + ABI define
    if (WIN32)
        set(NASM_FORMAT win64)
        set(NASM_DEFS "-DWINDOWS")
    elseif(APPLE)
        set(NASM_FORMAT macho64)
        set(NASM_DEFS "")
    else()
        set(NASM_FORMAT elf64)
        set(NASM_DEFS "")
    endif()

    set(CMAKE_ASM_NASM_FLAGS "-f ${NASM_FORMAT} ${NASM_DEFS}")

    set(ASM_SOURCES
        src/asm/secure_wipe.asm
        src/asm/xor_core.asm
    )

    add_library(vault_asm STATIC ${ASM_SOURCES})
else()
    message(STATUS "NASM not found — ASM sources skipped")
    add_library(vault_asm INTERFACE)
endif()

# ── Main executable ────────────────────────────────────────────────────────
add_executable(securevault
    src/main.cpp
    src/cli.cpp
)

target_include_directories(securevault PRIVATE include)

target_link_libraries(securevault PRIVATE
    vault_crypto
    vault_asm
)

# ── Benchmark executable ───────────────────────────────────────────────────
add_executable(securevault_bench
    src/benchmark_main.cpp
)

target_include_directories(securevault_bench PRIVATE include)

target_link_libraries(securevault_bench PRIVATE
    vault_crypto
)

# ── Tests ──────────────────────────────────────────────────────────────────
enable_testing()

add_executable(test_crypto
    tests/test_crypto.cpp
)

target_include_directories(test_crypto PRIVATE include)

target_link_libraries(test_crypto PRIVATE
    vault_crypto
)

add_test(NAME CryptoTests COMMAND test_crypto)

# CTest properties
set_tests_properties(CryptoTests PROPERTIES
    TIMEOUT 120
    PASS_REGULAR_EXPRESSION "Results:.*0 failed"
)

# ── Install ────────────────────────────────────────────────────────────────
install(TARGETS securevault RUNTIME DESTINATION bin)