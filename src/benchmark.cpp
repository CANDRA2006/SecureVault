#include <chrono>
#include <iostream>
#include <vector>    
#include <cstdint>    

void benchmark() {
    const size_t size = 10000000;

    std::vector<uint8_t> data(size, 0xAA);
    std::vector<uint8_t> key(size, 0x55);

    auto start = std::chrono::high_resolution_clock::now();

    for (size_t i = 0; i < size; i++)
        data[i] ^= key[i];

    auto end = std::chrono::high_resolution_clock::now();

    std::cout << "Benchmark complete\n";
}