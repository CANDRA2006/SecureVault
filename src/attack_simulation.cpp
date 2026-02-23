#include <iostream>
#include <cmath>

void simulate_attack(const std::string& password) {
    double charset = 94;
    double entropy = password.length() * std::log2(charset);

    std::cout << "Entropy: " << entropy << " bits\n";

    double guesses = std::pow(2, entropy);
    double seconds = guesses / 1e9;

    std::cout << "Estimated brute-force time (1B guesses/sec): "
              << seconds << " seconds\n";
}