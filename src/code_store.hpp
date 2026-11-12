// The decoded functions a run holds (CodeCache), the original's kept between runs (CodeStore), and the rebuilt
// image's (RebuiltStore).
#pragma once
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "cache_file.hpp"
#include "util.hpp"
#include "x64.hpp"

namespace verifier {

// The original's decoded functions kept in the cache directory between runs: the original does not change, so a
// function decoded once is read back instead of decoded again. Keyed by the original's snapshot key and the verifier
// build (the decoder). The functions a run decodes are added; the file is written again when there are new ones (once
// no function read from it is held).
class CodeStore {
 public:
  CodeStore(std::string path, std::string key);                                  // path empty: nothing kept
  std::shared_ptr<const Code> find(const Image& img, u64 start, u64 end) const;  // nullptr when not kept
  void add(const Code& c);                                                       // a function decoded this run
  void save();                                                                   // when functions were added

 private:
  struct Record {
    u64 start, end;
    size_t at;  // where in the file
    bool operator<(const Record& o) const { return std::make_pair(start, end) < std::make_pair(o.start, o.end); }
  };
  std::string path_, key_;
  std::shared_ptr<const MappedFile> file_;  // held by the functions read in place too
  std::vector<u16> mnems_;     // the file's mnemonic numbers -> this run's (Mnem ids are numbered as a run meets them)
  bool in_place_ = false;      // the numbers are the same: instructions and fields are read in place
  std::vector<Record> index_;  // the file's functions, sorted
  BinWriter added_;            // the functions decoded this run, as the file has them
};

// The rebuilt image's decoded functions kept between runs, for a build that changes few functions. A function is found
// again by its name and size wherever the link put it, and is used only when same_code_fields shows that the bytes
// there now decode as the kept bytes did (the same bytes outside the fields, relocations at the same places, no field
// that changes how the code decodes); its fields are then read from the bytes. Only functions whose shape is known are
// kept. Keyed by the verifier build (the decoder). VERIFIER_CHECK_FAST checks each function made so against a decode.
class RebuiltStore {
 public:
  RebuiltStore(std::string path, std::string key);  // path empty: nothing kept
  // the function at [start, end) of `img` named `name`, without a decode; nullptr when none kept decodes as it does
  std::shared_ptr<const Code> find(const Image& img, u64 start, u64 end, std::string_view name);
  void add(const Code& c, std::string_view name);  // a function decoded this run (kept when its shape is known)
  void save();                                     // the functions found or added this run, when that changed
  size_t found = 0, missed = 0;                    // finds answered and not (for VERIFIER_TIMING)

 private:
  struct Record {
    u64 key;
    size_t at;  // where in the file
    bool operator<(const Record& o) const { return std::make_pair(key, at) < std::make_pair(o.key, o.at); }
  };
  std::string path_, key_;
  std::unique_ptr<const MappedFile> file_;
  std::vector<u16> mnems_;  // the file's mnemonic numbers -> this run's
  std::vector<Record> index_;
  std::vector<bool> used_;               // by index_ entry: found this run (kept by save)
  BinWriter kept_;                       // what save writes: the functions found and added, as this run numbers them
  std::set<std::pair<u64, u64>> added_;  // (start, end) of those added
};

// The decoded functions a run holds, by (start, end): decoded (or read from a store) when first asked for, released
// when a comparison no longer needs them. The rebuilt image's cache finds its functions in a RebuiltStore by name.
class CodeCache {
 public:
  explicit CodeCache(const Image* img, CodeStore* store = nullptr) : img_(img), store_(store) {}
  CodeCache(const Image* img, RebuiltStore* store, std::function<std::string_view(u64)> name_of)
      : img_(img), rebuilt_store_(store), name_of_(std::move(name_of)) {}
  std::shared_ptr<const Code> code(u64 start, u64 end);
  void release(u64 start, u64 end) { live_.erase({start, end}); }
  void clear() { live_.clear(); }

 private:
  const Image* img_;
  CodeStore* store_ = nullptr;
  RebuiltStore* rebuilt_store_ = nullptr;
  std::function<std::string_view(u64)> name_of_;  // a rebuilt function's name ("" for none)
  std::map<std::pair<u64, u64>, std::shared_ptr<const Code>> live_;
};

}  // namespace verifier
