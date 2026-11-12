// The decoded functions a run holds (CodeCache), and the original's kept between runs (CodeStore).
#pragma once
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "cache_file.hpp"
#include "util.hpp"
#include "x64.hpp"

namespace verifier {

// The original's decoded functions kept in the cache directory between runs: the original does not change, so a
// function decoded once is read back instead of decoded again. Keyed by the original's snapshot key and the verifier
// build (the decoder). The functions a run decodes are added; the file is written again when there are new ones.
class CodeStore {
 public:
  CodeStore(std::string path, std::string key);  // path empty: nothing kept
  std::shared_ptr<const Code> find(const Image& img, u64 start, u64 end) const;  // nullptr when not kept
  void add(const Code& c);                                                        // a function decoded this run
  void save();                                                                    // when functions were added

 private:
  struct Record {
    u64 start, end;
    size_t at;  // where in the file
    bool operator<(const Record& o) const { return std::make_pair(start, end) < std::make_pair(o.start, o.end); }
  };
  std::string path_, key_;
  std::unique_ptr<const MappedFile> file_;
  std::vector<u16> mnems_;     // the file's mnemonic numbers -> this run's (Mnem ids are numbered as a run meets them)
  std::vector<Record> index_;  // the file's functions, sorted
  BinWriter added_;            // the functions decoded this run, as the file has them
};

// The decoded functions a run holds, by (start, end): decoded (or read from the store) when first asked for, released
// when a comparison no longer needs them
class CodeCache {
 public:
  explicit CodeCache(const Image* img, CodeStore* store = nullptr) : img_(img), store_(store) {}
  std::shared_ptr<const Code> code(u64 start, u64 end);
  void release(u64 start, u64 end) { live_.erase({start, end}); }

 private:
  const Image* img_;
  CodeStore* store_;
  std::map<std::pair<u64, u64>, std::shared_ptr<const Code>> live_;
};

}  // namespace verifier
