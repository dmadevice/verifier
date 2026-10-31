#include "content_hash.hpp"

#include <cstring>

namespace verifier {

namespace {

constexpr u64 P1 = 0x9E3779B185EBCA87ull, P2 = 0xC2B2AE3D27D4EB4Full, P3 = 0x165667B19E3779F9ull,
              P4 = 0x85EBCA77C2B2AE63ull, P5 = 0x27D4EB2F165667C5ull;

inline u64 rotl(u64 x, int r) { return (x << r) | (x >> (64 - r)); }
inline u64 read64(const char* p) { u64 v; std::memcpy(&v, p, 8); return v; }   // little-endian hosts
inline u32 read32(const char* p) { u32 v; std::memcpy(&v, p, 4); return v; }
inline u64 round(u64 acc, u64 in) { return rotl(acc + in * P2, 31) * P1; }
inline u64 merge(u64 acc, u64 v) { return (acc ^ round(0, v)) * P1 + P4; }

}  // namespace

u64 xxh64(std::string_view data, u64 seed) {
  const char* p = data.data();
  const char* end = p + data.size();
  u64 h;
  if (data.size() >= 32) {
    u64 v1 = seed + P1 + P2, v2 = seed + P2, v3 = seed, v4 = seed - P1;
    const char* limit = end - 32;
    do {
      v1 = round(v1, read64(p));
      v2 = round(v2, read64(p + 8));
      v3 = round(v3, read64(p + 16));
      v4 = round(v4, read64(p + 24));
      p += 32;
    } while (p <= limit);
    h = rotl(v1, 1) + rotl(v2, 7) + rotl(v3, 12) + rotl(v4, 18);
    h = merge(h, v1);
    h = merge(h, v2);
    h = merge(h, v3);
    h = merge(h, v4);
  } else {
    h = seed + P5;
  }
  h += u64(data.size());
  for (; p + 8 <= end; p += 8) h = rotl(h ^ round(0, read64(p)), 27) * P1 + P4;
  if (p + 4 <= end) {
    h = rotl(h ^ (u64(read32(p)) * P1), 23) * P2 + P3;
    p += 4;
  }
  for (; p < end; ++p) h = rotl(h ^ (u64(static_cast<unsigned char>(*p)) * P5), 11) * P1;
  h ^= h >> 33;
  h *= P2;
  h ^= h >> 29;
  h *= P3;
  h ^= h >> 32;
  return h;
}

std::string content_hash(std::string_view data) {
  static const char* digits = "0123456789abcdef";
  u64 w[2] = {xxh64(data, 0), xxh64(data, P1)};
  std::string out(32, '0');
  for (int i = 0; i < 16; ++i) {
    unsigned b = unsigned(w[i / 8] >> (8 * (7 - i % 8))) & 0xff;
    out[size_t(2 * i)] = digits[b >> 4];
    out[size_t(2 * i + 1)] = digits[b & 15];
  }
  return out;
}

std::string content_hash_file_if_present(const std::string& path) {
  std::string out;
  if (!with_contents_if_present(path, [&](std::string_view data) { out = content_hash(data); })) return "";
  return out;
}

}  // namespace verifier
