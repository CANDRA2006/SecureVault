#include <iostream>

void process(const std::string&, const std::string&, const std::string&);

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cout << "Usage: securevault <enc/dec> <file> <password>\n";
        return 1;
    }

    process(argv[1], argv[2], argv[3]);
    return 0;
}