#include "sha256.hpp"

#include <cstdio>
#include <cstring>

#if defined(__x86_64__) || defined(_M_X64)
#define VERIFIER_SHA_NI 1
#include <immintrin.h>
#ifdef _MSC_VER
#include <intrin.h>
#else
#include <cpuid.h>
#endif
#endif

#include "util.hpp"

namespace verifier {

namespace {
const std::uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
inline std::uint32_t rotr(std::uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

#ifdef VERIFIER_SHA_NI
bool have_sha_ni() {
#ifdef _MSC_VER
  int r[4];
  __cpuidex(r, 0, 0);
  if (r[0] < 7) return false;
  __cpuidex(r, 7, 0);
  bool sha = (r[1] >> 29) & 1;
  __cpuidex(r, 1, 0);
  return sha && ((r[2] >> 19) & 1) && ((r[2] >> 9) & 1);  // SHA, SSE4.1, SSSE3
#else
  unsigned a, b, c, d;
  if (!__get_cpuid_count(7, 0, &a, &b, &c, &d) || !((b >> 29) & 1)) return false;  // SHA
  if (!__get_cpuid(1, &a, &b, &c, &d)) return false;
  return ((c >> 19) & 1) && ((c >> 9) & 1);  // SSE4.1, SSSE3
#endif
}

// the x86 SHA extensions: n 64-byte blocks
#ifndef _MSC_VER
__attribute__((target("sha,sse4.1")))
#endif
void blocks_sha_ni(std::uint32_t state[8], const unsigned char* data, size_t n) {
  const __m128i MASK = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);
  __m128i tmp = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&state[0]));
  __m128i st1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&state[4]));
  tmp = _mm_shuffle_epi32(tmp, 0xB1);          // CDAB
  st1 = _mm_shuffle_epi32(st1, 0x1B);          // EFGH
  __m128i st0 = _mm_alignr_epi8(tmp, st1, 8);  // ABEF
  st1 = _mm_blend_epi16(st1, tmp, 0xF0);       // CDGH
  for (; n; --n, data += 64) {
    __m128i abef = st0, cdgh = st1;
    __m128i w[16];
    for (int g = 0; g < 4; ++g)
      w[g] = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(data + 16 * g)), MASK);
    for (int g = 4; g < 16; ++g) {
      __m128i t = _mm_sha256msg1_epu32(w[g - 4], w[g - 3]);
      t = _mm_add_epi32(t, _mm_alignr_epi8(w[g - 1], w[g - 2], 4));
      w[g] = _mm_sha256msg2_epu32(t, w[g - 1]);
    }
    for (int g = 0; g < 16; ++g) {
      __m128i msg = _mm_add_epi32(w[g], _mm_loadu_si128(reinterpret_cast<const __m128i*>(&K[4 * g])));
      st1 = _mm_sha256rnds2_epu32(st1, st0, msg);
      msg = _mm_shuffle_epi32(msg, 0x0E);
      st0 = _mm_sha256rnds2_epu32(st0, st1, msg);
    }
    st0 = _mm_add_epi32(st0, abef);
    st1 = _mm_add_epi32(st1, cdgh);
  }
  tmp = _mm_shuffle_epi32(st0, 0x1B);     // FEBA
  st1 = _mm_shuffle_epi32(st1, 0xB1);     // DCHG
  st0 = _mm_blend_epi16(tmp, st1, 0xF0);  // DCBA
  st1 = _mm_alignr_epi8(st1, tmp, 8);     // ABEF
  _mm_storeu_si128(reinterpret_cast<__m128i*>(&state[0]), st0);
  _mm_storeu_si128(reinterpret_cast<__m128i*>(&state[4]), st1);
}
#endif
}  // namespace

bool Sha256::force_scalar = false;

Sha256::Sha256() {
  const std::uint32_t init[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  std::memcpy(h_, init, sizeof init);
}

void Sha256::block(const unsigned char* p) {
  std::uint32_t w[64];
  for (int i = 0; i < 16; ++i)
    w[i] = (std::uint32_t(p[4 * i]) << 24) | (p[4 * i + 1] << 16) | (p[4 * i + 2] << 8) | p[4 * i + 3];
  for (int i = 16; i < 64; ++i) {
    std::uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
    std::uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  std::uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3], e = h_[4], f = h_[5], g = h_[6], h = h_[7];
  for (int i = 0; i < 64; ++i) {
    std::uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25), ch = (e & f) ^ (~e & g);
    std::uint32_t t1 = h + S1 + ch + K[i] + w[i];
    std::uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22), mj = (a & b) ^ (a & c) ^ (b & c);
    std::uint32_t t2 = S0 + mj;
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }
  h_[0] += a;
  h_[1] += b;
  h_[2] += c;
  h_[3] += d;
  h_[4] += e;
  h_[5] += f;
  h_[6] += g;
  h_[7] += h;
}

void Sha256::update(std::string_view data) {
  const unsigned char* p = reinterpret_cast<const unsigned char*>(data.data());
  size_t n = data.size();
  len_ += n;
  if (fill_) {
    size_t k = std::min(n, 64 - fill_);
    std::memcpy(buf_ + fill_, p, k);
    fill_ += k;
    p += k;
    n -= k;
    if (fill_ == 64) {
      block(buf_);
      fill_ = 0;
    }
  }
#ifdef VERIFIER_SHA_NI
  static const bool ni = have_sha_ni();
  if (ni && !force_scalar && n >= 64) {
    blocks_sha_ni(h_, p, n / 64);
    p += n / 64 * 64;
    n %= 64;
  }
#endif
  while (n >= 64) {
    block(p);
    p += 64;
    n -= 64;
  }
  if (n) {
    std::memcpy(buf_, p, n);
    fill_ = n;
  }
}

std::string Sha256::hexdigest() {
  std::uint64_t bits = len_ * 8;
  unsigned char pad = 0x80;
  update(std::string_view(reinterpret_cast<char*>(&pad), 1));
  unsigned char zero = 0;
  while (fill_ != 56) update(std::string_view(reinterpret_cast<char*>(&zero), 1));
  unsigned char lenb[8];
  for (int i = 0; i < 8; ++i) lenb[i] = static_cast<unsigned char>(bits >> (56 - 8 * i));
  update(std::string_view(reinterpret_cast<char*>(lenb), 8));
  char out[65];
  for (int i = 0; i < 8; ++i) std::snprintf(out + 8 * i, 9, "%08x", h_[i]);
  return std::string(out, 64);
}

std::string sha256_hex(std::string_view data) {
  Sha256 h;
  h.update(data);
  return h.hexdigest();
}

std::string sha256_file(const std::string& path) {
  Sha256 h;
  with_contents(path, [&](std::string_view data) { h.update(data); });
  return h.hexdigest();
}

std::string sha256_file_if_present(const std::string& path) {
  Sha256 h;
  return with_contents_if_present(path, [&](std::string_view data) { h.update(data); }) ? h.hexdigest() : "";
}

}  // namespace verifier
