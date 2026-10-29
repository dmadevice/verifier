#include "util.hpp"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <new>
#include <sstream>
#include <stdexcept>

#ifdef _WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <sys/mman.h>
#endif

namespace verifier {

#ifdef _WIN32
const char kSep = '\\';
#else
const char kSep = '/';
#endif

std::string read_file(const std::string& path) {
  std::FILE* f = std::fopen(path.c_str(), "rb");
  if (!f) throw std::runtime_error("cannot read " + path);
  std::string out;
  if (std::fseek(f, 0, SEEK_END) == 0) {   // read in place at the file's size, then whatever follows
    long n = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    if (n > 0) {
      out.resize(size_t(n));
      out.resize(std::fread(out.data(), 1, out.size(), f));
    }
  }
  char buf[1 << 16];
  size_t got;
  while ((got = std::fread(buf, 1, sizeof buf, f)) > 0) out.append(buf, got);
  bool err = std::ferror(f) != 0;
  std::fclose(f);
  if (err) throw std::runtime_error("cannot read " + path);
  return out;
}

void for_each_file_line(const std::string& path, const std::function<void(std::string_view)>& fn) {
  std::FILE* f = std::fopen(path.c_str(), "rb");
  if (!f) throw std::runtime_error("cannot read " + path);
  std::string carry;
  std::vector<char> buf(1 << 20);
  size_t got;
  while ((got = std::fread(buf.data(), 1, buf.size(), f)) > 0) {
    std::string_view block(buf.data(), got);
    size_t last = block.find_last_of("\n\r");
    if (last == std::string_view::npos) { carry.append(block); continue; }
    // a "\r" ending the block may be the first half of "\r\n": keep it for the next block
    if (block[last] == '\r' && last + 1 == got) {
      size_t prev = last ? block.find_last_of("\n\r", last - 1) : std::string_view::npos;
      if (prev == std::string_view::npos) { carry.append(block); continue; }
      last = prev;
    }
    std::string_view head = block.substr(0, last + 1);
    if (!carry.empty()) {
      size_t first = head.find_first_of("\n\r");
      size_t e = first + 1;
      if (head[first] == '\r' && e < head.size() && head[e] == '\n') ++e;
      carry.append(head.substr(0, e));
      for_each_line(carry, fn);
      carry.clear();
      head = head.substr(e);
    }
    for_each_line(head, fn);
    carry.assign(block.substr(last + 1));
  }
  std::fclose(f);
  if (!carry.empty()) for_each_line(carry, fn);
}

bool file_exists(const std::string& path) {
  std::error_code ec;
  return std::filesystem::is_regular_file(path, ec);
}

bool write_file_atomic(const std::string& path, std::string_view data) {
  std::string tmp = path + ".tmp";
  {
    std::ofstream f(tmp, std::ios::binary);
    if (!f) return false;
    f.write(data.data(), std::streamsize(data.size()));
    if (!f) return false;
  }
  std::error_code ec;
  std::filesystem::rename(tmp, path, ec);
  if (ec) std::filesystem::remove(tmp, ec);
  return !ec;
}

std::vector<std::string> read_lines(const std::string& path) {
  std::vector<std::string> out;
  for_each_line(read_file(path), [&](std::string_view l) { out.emplace_back(l); });
  return out;
}

std::string hex_signed(i64 v) { return v < 0 ? "-" + hex(u64(-v)) : hex(u64(v)); }

std::string hex(u64 v) {
  char buf[24];
  std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(v));
  return buf;
}

std::string hex_bytes(std::string_view b) {
  static const char* d = "0123456789abcdef";
  std::string out;
  out.reserve(b.size() * 2);
  for (unsigned char c : b) { out += d[c >> 4]; out += d[c & 15]; }
  return out;
}

u64 parse_hex(std::string_view s) {
  if (starts_with(s, "0x") || starts_with(s, "0X")) s.remove_prefix(2);
  u64 v = 0;
  for (char c : s) {
    int d = hex_digit(c);
    if (d < 0) throw std::runtime_error("bad hex: " + std::string(s));
    v = v * 16 + d;
  }
  return v;
}

bool starts_with(std::string_view s, std::string_view p) { return s.substr(0, p.size()) == p; }
bool ends_with(std::string_view s, std::string_view p) { return s.size() >= p.size() && s.substr(s.size() - p.size()) == p; }

std::string strip(std::string_view s) {
  size_t a = 0, b = s.size();
  while (a < b && is_space(s[a])) ++a;
  while (b > a && is_space(s[b - 1])) --b;
  return std::string(s.substr(a, b - a));
}

std::string rstrip(std::string_view s) {
  size_t b = s.size();
  while (b > 0 && is_space(s[b - 1])) --b;
  return std::string(s.substr(0, b));
}

std::string rstrip_char(std::string_view s, char c) {
  size_t b = s.size();
  while (b > 0 && s[b - 1] == c) --b;
  return std::string(s.substr(0, b));
}

std::vector<std::string> split_ws(std::string_view s) {
  std::vector<std::string> out;
  size_t i = 0, n = s.size();
  while (i < n) {
    while (i < n && is_space(s[i])) ++i;
    size_t j = i;
    while (j < n && !is_space(s[j])) ++j;
    if (j > i) out.emplace_back(s.substr(i, j - i));
    i = j;
  }
  return out;
}

std::string join(const std::vector<std::string>& v, std::string_view sep) {
  std::string out;
  for (size_t i = 0; i < v.size(); ++i) { if (i) out += sep; out += v[i]; }
  return out;
}

std::string replace_all(std::string s, std::string_view from, std::string_view to) {
  if (from.empty()) return s;
  size_t p = 0;
  while ((p = s.find(from, p)) != std::string::npos) { s.replace(p, from.size(), to); p += to.size(); }
  return s;
}

std::string lower(std::string s) {
  for (auto& c : s) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  return s;
}

ZeroBuffer::ZeroBuffer(size_t n) : n_(n) {
  if (!n) return;
#ifdef _WIN32
  p_ = static_cast<char*>(VirtualAlloc(nullptr, n, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
  if (!p_) throw std::bad_alloc();
#else
  void* p = mmap(nullptr, n, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) throw std::bad_alloc();
  p_ = static_cast<char*>(p);
#endif
}

ZeroBuffer::~ZeroBuffer() {
  if (!p_) return;
#ifdef _WIN32
  VirtualFree(p_, 0, MEM_RELEASE);
#else
  munmap(p_, n_);
#endif
}

std::string percent(u64 part, u64 whole) {
  char buf[32];
  std::snprintf(buf, sizeof buf, "%.2f%%", whole ? 100.0 * double(part) / double(whole) : 0.0);
  return buf;
}

static bool is_sep(char c) {
#ifdef _WIN32
  return c == '\\' || c == '/';
#else
  return c == '/';
#endif
}

std::string normpath(const std::string& p) {
  std::filesystem::path fp(p);
  std::string s = fp.lexically_normal().make_preferred().string();
  while (s.size() > 1 && is_sep(s.back())) s.pop_back();
  return s.empty() ? "." : s;
}

std::string abspath(const std::string& p) {
  std::error_code ec;
  return normpath(std::filesystem::absolute(p, ec).string());
}

std::string path_join(const std::string& a, const std::string& b) {
  if (a.empty()) return b;
  if (is_sep(a.back())) return a + b;
  return a + kSep + b;
}

std::string dirname(const std::string& p) {
  size_t i = p.size();
  while (i > 0 && !is_sep(p[i - 1])) --i;
  if (i == 0) return "";
  std::string d = p.substr(0, i);
  while (d.size() > 1 && is_sep(d.back())) d.pop_back();
  return d;
}

std::string basename(const std::string& p) {
  size_t i = p.size();
  while (i > 0 && !is_sep(p[i - 1])) --i;
  return p.substr(i);
}

std::string relpath(const std::string& path, const std::string& root) {
  std::filesystem::path a = std::filesystem::path(abspath(path)), b = std::filesystem::path(abspath(root));
#ifdef _WIN32
  if (lower(a.root_name().string()) != lower(b.root_name().string())) return path;   // another drive: as given
#endif
  std::string r = a.lexically_relative(b).make_preferred().string();
  return r.empty() ? "." : r;
}

}  // namespace verifier
