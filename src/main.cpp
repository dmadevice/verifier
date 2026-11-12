#include <cstdio>
#include <exception>

#include "verify.hpp"

// a bad input (an unreadable file, a malformed line or table) ends the run with its reason, not an abort
int main(int argc, char** argv) {
  try {
    return verifier::run(argc, argv);
  } catch (const std::exception& e) {
    std::fprintf(stderr, "verifier: %s\n", e.what());
    return 2;
  }
}
