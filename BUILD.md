# SecureVault — Build Instructions

## Prerequisites

### Ubuntu / Debian
```bash
sudo apt-get install g++ libssl-dev nasm cmake
```

### macOS
```bash
brew install openssl nasm cmake
```

### Windows
- Install [Visual Studio Build Tools](https://aka.ms/vs/17/release/vs_BuildTools.exe)
- Install [OpenSSL for Windows](https://slproweb.com/products/Win32OpenSSL.html)
- Install [NASM](https://www.nasm.us/)

---

## Build with CMake (recommended)

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# Run tests
./test_crypto

# Run self-test
./securevault self-test
```

### macOS with Homebrew OpenSSL
```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release \
         -DOPENSSL_ROOT_DIR=$(brew --prefix openssl)
make -j$(nproc)
```

---

## Build with g++ directly (no CMake needed)

```bash
mkdir build

# Compile objects
g++ -std=c++17 -O2 -Iinclude -c src/crypto/crypto_engine.cpp  -o build/crypto_engine.o
g++ -std=c++17 -O2 -Iinclude -c src/file_io.cpp               -o build/file_io.o
g++ -std=c++17 -O2 -Iinclude -c src/benchmark.cpp             -o build/benchmark.o
g++ -std=c++17 -O2 -Iinclude -c src/attack_simulation.cpp     -o build/attack_sim.o
g++ -std=c++17 -O2 -Iinclude -c src/cli.cpp                   -o build/cli.o
g++ -std=c++17 -O2 -Iinclude -c src/main.cpp                  -o build/main.o

# Link main binary
g++ build/crypto_engine.o build/file_io.o build/benchmark.o build/attack_sim.o \
    build/cli.o build/main.o \
    -lssl -lcrypto -o build/securevault

# Link benchmark binary
g++ -std=c++17 -O2 -Iinclude -c src/benchmark_main.cpp -o build/bench_main.o
g++ build/crypto_engine.o build/file_io.o build/benchmark.o build/attack_sim.o \
    build/bench_main.o -lssl -lcrypto -o build/securevault_bench

# Link test binary
g++ -std=c++17 -O2 -Iinclude -c tests/test_crypto.cpp -o build/test_crypto.o
g++ build/crypto_engine.o build/file_io.o build/benchmark.o build/attack_sim.o \
    build/test_crypto.o -lssl -lcrypto -o build/test_crypto
```

### NASM (optional, for ASM optimizations)
```bash
# Linux
nasm -f elf64 src/asm/secure_wipe.asm -o build/secure_wipe.o
nasm -f elf64 src/asm/xor_core.asm    -o build/xor_core.o
# Add build/secure_wipe.o build/xor_core.o to the link step

# macOS
nasm -f macho64 src/asm/secure_wipe.asm -o build/secure_wipe.o
nasm -f macho64 src/asm/xor_core.asm    -o build/xor_core.o

# Windows
nasm -f win64 -DWINDOWS src/asm/secure_wipe.asm -o build/secure_wipe.o
nasm -f win64 -DWINDOWS src/asm/xor_core.asm    -o build/xor_core.o
```

---

## Verify build is correct

```bash
# All 43 tests must pass
./build/test_crypto

# Built-in self test
./build/securevault self-test
```

Expected output:
```
=== Results: 43 tests, 43 passed, 0 failed ===
Self-test PASSED
```