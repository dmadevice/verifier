// Small helpers shared by the verifier: byte strings, hex, files, text.
#pragma once
#include <cstdint>
#include <cstring>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace verifier {

using u8 = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;
using i8 = std::int8_t;
using i32 = std::int32_t;
using i64 = std::int64_t;
using Bytes = std::string;   // raw bytes

std::string read_file(const std::string& path);   // throws on error
bool file_exists(const std::string& path);
// writes a temporary file beside `path`, then renames it over `path` (readers see the old file or the new one);
// false (and no file) on failure
bool write_file_atomic(const std::string& path, std::string_view data);
std::vector<std::string> read_lines(const std::string& path);   // splitlines() semantics, newline stripped
// for_each_line over a file read in blocks (bounded memory)
void for_each_file_line(const std::string& path, const std::function<void(std::string_view)>& fn);
// fn(line) for each line of `data` (as read_lines splits them), without copying
template <class F>
void for_each_line(std::string_view data, F&& fn) {
  size_t i = 0, n = data.size();
  while (i < n) {
    const char* nl = static_cast<const char*>(std::memchr(data.data() + i, '\n', n - i));
    size_t j = nl ? size_t(nl - data.data()) : n;
    if (const void* cr = std::memchr(data.data() + i, '\r', j - i)) j = size_t(static_cast<const char*>(cr) - data.data());
    fn(data.substr(i, j - i));
    if (j < n && data[j] == '\r' && j + 1 < n && data[j + 1] == '\n') j += 2;
    else if (j < n) j += 1;
    i = j;
  }
}

std::string hex(u64 v);                       // "0x1a2b"
std::string hex_signed(i64 v);                // "0x1a2b", "-0x1a2b"
std::string hex_bytes(std::string_view b);    // "1a2b..."
u64 parse_hex(std::string_view s);            // "0x..." or digits

bool starts_with(std::string_view s, std::string_view p);
bool ends_with(std::string_view s, std::string_view p);
std::string strip(std::string_view s);        // without leading and trailing whitespace
std::string rstrip(std::string_view s);       // without trailing whitespace
std::string rstrip_char(std::string_view s, char c);
std::vector<std::string> split_ws(std::string_view s);   // whitespace-separated fields
inline bool is_space(char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'; }
inline bool is_digit(char c) { return c >= '0' && c <= '9'; }
inline int hex_digit(char c) {                 // 0..15, -1 for a non-hex character
  return is_digit(c) ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
}
// a decimal number of at most 19 digits at s[i]: its value, and where it ends (false when there are no digits)
inline bool parse_dec(std::string_view s, size_t i, u64& v, size_t& end) {
  size_t j = i;
  v = 0;
  while (j < s.size() && is_digit(s[j])) v = v * 10 + u64(s[j++] - '0');
  end = j;
  return j > i && j - i <= 19;
}
inline bool is_word(char c) {                  // [A-Za-z0-9_]
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
}
std::string join(const std::vector<std::string>& v, std::string_view sep);
std::string replace_all(std::string s, std::string_view from, std::string_view to);
std::string lower(std::string s);

// std::string-keyed hash map that also looks up by std::string_view (no temporary strings)
struct SvHash {
  using is_transparent = void;
  size_t operator()(std::string_view s) const { return std::hash<std::string_view>()(s); }
};
template <class V>
using SvMap = std::unordered_map<std::string, V, SvHash, std::equal_to<>>;
using NameMap = std::unordered_map<u64, std::string_view>;   // VA -> name (views of text kept for the run)
// keyed by views of text kept elsewhere
template <class V>
using SvViewMap = std::unordered_map<std::string_view, V, SvHash>;

inline u32 le32(const char* p) { u32 v; std::memcpy(&v, p, 4); return v; }
inline u64 le64(const char* p) { u64 v; std::memcpy(&v, p, 8); return v; }
inline u16 le16(const char* p) { u16 v; std::memcpy(&v, p, 2); return v; }

// n zero bytes in pages from the operating system, which take no memory until written
class ZeroBuffer {
 public:
  explicit ZeroBuffer(size_t n);
  ~ZeroBuffer();
  ZeroBuffer(const ZeroBuffer&) = delete;
  ZeroBuffer& operator=(const ZeroBuffer&) = delete;
  char* data() { return p_; }
  size_t size() const { return n_; }

 private:
  char* p_ = nullptr;
  size_t n_ = 0;
};

std::string percent(u64 part, u64 whole);     // "12.34%"

// path relative to root ('/' or '\\' as the platform separator)
std::string relpath(const std::string& path, const std::string& root);
std::string path_join(const std::string& a, const std::string& b);
std::string abspath(const std::string& p);
std::string normpath(const std::string& p);
std::string dirname(const std::string& p);
std::string basename(const std::string& p);
extern const char kSep;

}  // namespace verifier
