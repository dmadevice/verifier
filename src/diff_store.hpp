// The DIFF report's instruction diffs and categories kept in the cache directory between runs: both are functions of
// the two token streams (and the instructions' offsets, and the original's names they show), so a function whose
// tokens are as they were is not aligned and written again. The file is keyed by the verifier (its own hash) and the
// original's names (the snapshot's key); each entry by a 128-bit hash of the tokens and offsets.
#pragma once
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "report.hpp"

namespace verifier {

class DiffStore {
 public:
  DiffStore(std::string path, const std::string& key);  // path empty: nothing kept
  struct Entry {
    std::string category;
    std::vector<std::string> diff;
  };
  // classify(ot, rt) and insn_diff(...) for these tokens: from the file when it has them, else made here
  Entry get(const std::vector<u32>& o_off, const std::vector<u32>& r_off, const Toks& ot, const Toks& rt,
            const NameOf& names);
  void save();  // the entries this run used, when some were made here
  struct Stats {
    size_t hits = 0, misses = 0;
  };
  Stats stats() const { return stats_; }

 private:
  std::string path_, key_;
  std::unique_ptr<const MappedFile> file_;
  struct Index {
    u64 k0, k1, offset, size;
  };
  const Index* index_ = nullptr;
  size_t nindex_ = 0;
  std::string_view blobs_;
  // this run's entries: one made here, or a view of the file's (no copy: one is made only when the file is rewritten,
  // before its mapping is released)
  struct Used {
    std::string made;
    std::string_view in_file;
    std::string_view blob() const { return made.empty() ? in_file : std::string_view(made); }
  };
  std::map<std::pair<u64, u64>, Used> used_;
  Stats stats_;
  void load();
};

}  // namespace verifier
