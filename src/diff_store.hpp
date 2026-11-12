// A DIFF's report from its code (its category from the instructions, its instruction diff, its first difference) kept
// in the cache directory between runs, so a DIFF whose code and targets are as they were is not aligned and written
// again. The file is keyed by the verifier (its own hash) and the original's inputs (the snapshot's key), which fix
// the original's code and names; each entry by a 128-bit hash of everything else the report reads: both functions'
// places and bytes, the rebuilt one's address fields, what each stands for in the alignment, what its name resolves
// to, and the bytes there when it is a compiler constant.
#pragma once
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "report.hpp"

namespace verifier {

// what the report of a DIFF takes from its code
struct DiffReport {
  std::optional<Category> category;  // nullopt: the instructions are the same as tokens (the problems decide)
  CodeDiff diff;
  std::string first_orig, first_rebuilt;  // the first difference's instructions, as the decoder writes them
  bool operator==(const DiffReport& o) const {
    return category == o.category && diff.differs == o.diff.differs && diff.first == o.diff.first &&
           diff.lines == o.diff.lines && first_orig == o.first_orig && first_rebuilt == o.first_rebuilt;
  }
};

class DiffStore {
 public:
  DiffStore(std::string path, const std::string& key);  // path empty: nothing kept
  // `make()` for this DIFF: from the file when it has it, else made here. With `check` on, each report from the file
  // is made again too, and a difference throws.
  DiffReport get(const Code& oc, const Code& rc, const DiffContext& cx, const std::function<DiffReport()>& make);
  void save();  // the entries this run used, when some were made here
  bool check = false;
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
  // this run's entries: one made here, or a view of the file's (copied only when the file is rewritten, before its
  // mapping is released)
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
