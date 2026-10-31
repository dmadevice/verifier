// Files in the cache directory: a header (a magic line naming the format, then the key the contents depend on), then
// binary data (little-endian hosts) written and read with the helpers below. A file that does not start with the
// header this run expects is not used; a file is only ever replaced whole.
#pragma once
#include <cstring>
#include <memory>
#include <string>
#include <string_view>
#include <type_traits>

#include "util.hpp"

namespace verifier {

std::string cache_header(std::string_view magic, std::string_view key);   // magic + key + "\n"
// the file at `path` when it starts with `header`, mapped (else nullptr: absent, unreadable or another header)
std::unique_ptr<const MappedFile> open_cache_file(const std::string& path, std::string_view header);
// writes the file whole, creating its directory; false on failure (the cache is then only not kept)
bool write_cache_file(const std::string& path, std::string_view data);

class BinWriter {
 public:
  template <class T>
  void put(const T& v) {
    static_assert(std::is_trivially_copyable_v<T>);
    out.append(reinterpret_cast<const char*>(&v), sizeof v);
  }
  template <class T>
  void array(const T* p, size_t n) {   // n items, without their count
    static_assert(std::is_trivially_copyable_v<T>);
    out.append(reinterpret_cast<const char*>(p), n * sizeof(T));
  }
  void str(std::string_view s) { put(u32(s.size())); out += s; }   // u32 length, then the bytes
  void pad8() { out.append((8 - out.size() % 8) % 8, '\0'); }      // to a multiple of 8 from the file's start
  std::string out;
};

// Reads from `in` (the whole file) at a position; after the first read past the end every read fails (ok() false)
class BinReader {
 public:
  BinReader(std::string_view in, size_t at) : in_(in), p_(at) {}
  template <class T>
  bool get(T& v) {
    static_assert(std::is_trivially_copyable_v<T>);
    std::string_view b = take(sizeof v);
    if (ok_) std::memcpy(&v, b.data(), sizeof v);
    return ok_;
  }
  bool str(std::string& s) {
    u32 n = 0;
    if (get(n)) s.assign(take(n));
    return ok_;
  }
  std::string_view take(size_t n) {   // the next n bytes, as a view of the file
    if (!ok_ || in_.size() - p_ < n) { ok_ = false; return {}; }
    std::string_view v = in_.substr(p_, n);
    p_ += n;
    return v;
  }
  void pad8() { take((8 - p_ % 8) % 8); }
  bool ok() const { return ok_; }
  bool done() const { return p_ == in_.size(); }

 private:
  std::string_view in_;
  size_t p_;
  bool ok_ = true;
};

}  // namespace verifier
