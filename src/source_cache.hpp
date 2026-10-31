// Each source file's annotations kept in the cache directory between runs (see SourceCache).
#pragma once
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "annotations.hpp"

namespace verifier {

// Each source file's annotations kept in the cache directory between runs, with its content hash (for the replay
// key): a file whose size and modification time are as they were, and that is older than `recent` (a change in the
// same tick of the file clock could leave both as they were), is not read again. Keyed by the module and the parser
// (the verifier's own hash).
class SourceCache {
 public:
  struct Ann {
    std::string kind;
    u64 va;
    std::string name;
    AnnotationFlags flags;
    int line;
  };
  struct Ign {
    int line;
    std::string text;
  };
  struct Entry {
    std::string hash;
    std::vector<Ann> anns;
    std::vector<Ign> ignored;
  };
  SourceCache(std::string path, std::string key, i64 recent);  // path empty: nothing kept
  const Entry* find(const ListedFile& f) const;                // the file's entry when it can be used
  void keep(const ListedFile& f, const Entry& e);              // this run's entry for the file
  void save();                                                 // when an entry was made or the files listed differ
  struct Stats {
    size_t hits = 0, misses = 0;
  };
  Stats stats() const { return stats_; }

 private:
  std::string path_, key_;
  i64 recent_;
  struct Stored {
    u64 size;
    i64 time;
    Entry e;
  };
  std::unordered_map<std::string, Stored> old_;
  std::vector<std::pair<ListedFile, Entry>> new_;
  mutable Stats stats_;
  bool changed_ = false;
};

}  // namespace verifier
