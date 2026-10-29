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
std::string hex_bytes(std::string_view b);    // "1a2b..."
u64 parse_hex(std::string_view s);            // "0x..." or digits

bool starts_with(std::string_view s, std::string_view p);
bool ends_with(std::string_view s, std::string_view p);
std::string strip(std::string_view s);        // without leading and trailing whitespace
std::string rstrip_char(std::string_view s, char c);
std::vector<std::string> split_ws(std::string_view s);   // whitespace-separated fields
bool is_space(char c);
bool is_word(char c);                          // [A-Za-z0-9_]
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

inline u32 le32(const char* p) { u32 v; std::memcpy(&v, p, 4); return v; }
inline u64 le64(const char* p) { u64 v; std::memcpy(&v, p, 8); return v; }
inline u16 le16(const char* p) { u16 v; std::memcpy(&v, p, 2); return v; }

// x with three decimals (correctly rounded, like printf)
std::string fixed3(double x);
// a quoted string literal: single quotes unless it contains one and no double quote (the summary's categories)
std::string py_repr(std::string_view s);

// os.path.relpath(path, root) with '/' or '\\' as the platform separator
std::string relpath(const std::string& path, const std::string& root);
std::string path_join(const std::string& a, const std::string& b);
std::string abspath(const std::string& p);
std::string normpath(const std::string& p);
std::string dirname(const std::string& p);
std::string basename(const std::string& p);
extern const char kSep;

}  // namespace verifier
