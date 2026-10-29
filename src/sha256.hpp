// SHA-256 (the original image check and cache keys).
#pragma once
#include <cstdint>
#include <string>
#include <string_view>

namespace verifier {

class Sha256 {
 public:
  Sha256();
  void update(std::string_view data);
  std::string hexdigest();   // finalises
  static bool force_scalar;  // tests: the portable code even where the CPU has SHA instructions

 private:
  void block(const unsigned char* p);
  std::uint32_t h_[8];
  unsigned char buf_[64];
  std::uint64_t len_ = 0;
  size_t fill_ = 0;
};

std::string sha256_hex(std::string_view data);
std::string sha256_file(const std::string& path);

}  // namespace verifier
