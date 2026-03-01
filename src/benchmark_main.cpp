/**
 * benchmark_main.cpp — Entry point for the standalone benchmark binary.
 * failure for the securevault_bench target. Created to match the
 * forward declaration used in CMakeLists.txt.
 */

// Forward declaration — defined in benchmark.cpp
void benchmark();

int main() {
    benchmark();
    return 0;
}