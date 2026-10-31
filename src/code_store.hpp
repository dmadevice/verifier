// Decoded functions kept on disk between runs (the cache directory), one file per image: a function's decoded form
// (Code) is a function of its bytes, the relocations in it, where it is, the image's sections and the decoder, so it
// is used again when all of those are as they were. The file is keyed by the decoder (the verifier's own hash) and
// the image's base and headers; each function by its range, checked against its bytes and relocations.
#pragma once
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "x64.hpp"

namespace verifier {

class CodeStore {
 public:
  // `path` empty: nothing kept. `decoder`: what decodes (the verifier's hash). A rewrite keeps the entries a run did
  // not ask for that still hold.
  CodeStore(std::string path, const Image& img, const std::string& decoder);
  std::shared_ptr<const Code> code(u64 start,
                                   u64 end);  // from the file when it holds this function as it is, else decoded
  void save();                                // when something was decoded: the file rewritten
  struct Stats {
    size_t hits = 0, misses = 0;
  };
  Stats stats() const { return stats_; }

 private:
  std::string path_, key_;
  const Image& img_;
  std::unique_ptr<const MappedFile> file_;
  struct Index {
    u64 start, end, check, offset, size;
  };
  const Index* index_ = nullptr;
  size_t nindex_ = 0;
  std::string_view blobs_;
  std::vector<u16> mnem_;  // the file's mnemonic ids -> this run's
  // the functions decoded here (not in the file as they are): (start, end) -> (check, entry as written)
  std::map<std::pair<u64, u64>, std::pair<u64, std::string>> decoded_;
  Stats stats_;
  bool dirty_ = false;
  u64 check(u64 start, u64 end) const;
  std::string blob(const Code& c) const;  // in this run's mnemonic ids; save() writes the table that names them
  std::shared_ptr<const Code> from_blob(u64 start, u64 end, std::string_view b) const;  // nullptr: damaged
  void load();
  void fail();  // the file not used (and released)
};

// The decoded functions a run holds, by (start, end): from the store when there is one, else decoded; released when a
// comparison no longer needs them
class CodeCache {
 public:
  explicit CodeCache(const Image* img, CodeStore* store = nullptr) : img_(img), store_(store) {}
  std::shared_ptr<const Code> code(u64 start, u64 end);
  void release(u64 start, u64 end) { live_.erase({start, end}); }
  struct Stats {
    size_t functions = 0, insns = 0, code_bytes = 0;
  };
  Stats stats() const {
    Stats s;
    for (auto& [k, c] : live_) {
      ++s.functions;
      s.insns += c->insns.size();
      s.code_bytes += c->code.size();
    }
    return s;
  }

 private:
  const Image* img_;
  CodeStore* store_;  // decoded functions kept between runs (none: decoded here)
  std::map<std::pair<u64, u64>, std::shared_ptr<const Code>> live_;
};

}  // namespace verifier
