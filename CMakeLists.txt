cmake_minimum_required(VERSION 3.15)
project(SecureVault)

set(CMAKE_CXX_STANDARD 17)

enable_language(ASM_NASM)

file(GLOB_RECURSE SOURCES
    src/*.cpp
    src/asm/*.asm
)

add_executable(securevault ${SOURCES})

target_include_directories(securevault PRIVATE include)

find_package(OpenSSL REQUIRED)

target_link_libraries(securevault
    OpenSSL::SSL
    OpenSSL::Crypto
)