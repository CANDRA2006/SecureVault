#include <fstream>
#include <iostream>
#include <vector>
#include "aes.h"
#include "pbkdf2.h"

std::vector<uint8_t> readFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    return std::vector<uint8_t>(
        std::istreambuf_iterator<char>(file),
        std::istreambuf_iterator<char>()
    );
}

void writeFile(const std::string& filename, const std::vector<uint8_t>& data) {
    std::ofstream file(filename, std::ios::binary | std::ios::trunc);
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

void process(const std::string& mode,
             const std::string& filename,
             const std::string& password)
{
    auto data = readFile(filename);

    if (data.empty()) {
        std::cerr << "File kosong atau gagal dibaca\n";
        return;
    }

    auto key = derive_key(password);

    AES256 aes(key);

    if (mode == "enc") {
        aes.encrypt(data);
        writeFile(filename, data);
        std::cout << "Encrypted.\n";
    }
    else if (mode == "dec") {
        aes.decrypt(data);
        writeFile(filename, data);
        std::cout << "Decrypted.\n";
    }
    else {
        std::cerr << "Mode tidak dikenal\n";
    }
}