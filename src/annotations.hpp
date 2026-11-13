// Source annotations: `// FUNCTION: <module> 0x<va>` and friends, read from the source trees.
#pragma once
#include <deque>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "util.hpp"

namespace verifier {

// What an annotation says its definition is
enum class Kind : u8 { Function, Stub, Synthetic, Template, Library, Global, Vtable };
std::string_view kind_name(Kind k);                     // as written in source: FUNCTION, STUB, ...
std::optional<Kind> kind_named(std::string_view name);  // the kind written `name`

struct AnnotationFlags {
  bool folded = false;  // FOLDED: identical-code folding gave several functions the address
  bool dtor = false;    // the definition is a destructor
  std::string sig;      // the parameter list it pairs with (normalised; "" for any)
};

struct Annotation {
  Kind kind = Kind::Function;
  u64 va = 0;
  std::string name;
  AnnotationFlags flags;
  std::string_view path;  // text kept for the run (keep_text)
  int line = 0;
  // what the rebuilt names are looked up by, worked out from the name once (kept in the sources cache) when `keyed`:
  // the name as norm_name gives it (a VTABLE's with "::`vftable'"; "" when that is the name itself), and a destructor's
  // scalar deleting destructor's (see pick_destructor)
  bool keyed = false;
  std::string key, deleting_key;
};
void set_keys(Annotation& a);  // a's keys, from its kind, name and destructor flag

struct Ignored {
  std::string path;
  int line;
  std::string text;
};

std::optional<std::string> sig_flag(const AnnotationFlags& flags);  // the parameter list, if any

// The files under root: each directory's files (sorted by name), then its subdirectories (sorted by name), with their
// sizes and modification times (on Windows from the directory listing, without opening each file)
struct ListedFile {
  std::string path;
  u64 size = 0;
  i64 time = 0;  // the file clock's ticks
};
std::vector<ListedFile> list_files(const std::string& root);

// Each source file's annotations kept in the cache directory between runs, by path: a file whose size and modification
// time are as they were, and that is older than `recent` (a change in the same tick of the file clock could leave both
// as they were), is not read again. Keyed by the module and the parser (the verifier build).
class SourceCache {
 public:
  struct Entry {
    struct Ann {
      Kind kind;
      u64 va;
      std::string name;
      AnnotationFlags flags;
      int line;
      std::string key, deleting_key;  // the annotation's (keyed)
    };
    struct Ign {
      int line;
      std::string text;
    };
    std::vector<Ann> anns;
    std::vector<Ign> ignored;
  };
  SourceCache(std::string path, std::string key, i64 recent);  // path empty: nothing kept
  const Entry* find(const ListedFile& f) const;                // the file's entry when it can be used
  void keep(const ListedFile& f, Entry e);                     // this run's entry for the file
  void keep(const ListedFile& f, const Entry* found);          // the entry find() gave (not copied)
  void save();                                                 // when an entry changed or the files listed differ

 private:
  std::string path_, key_;
  i64 recent_;
  struct Stored {
    u64 size;
    i64 time;
    Entry e;
  };
  std::unordered_map<std::string, Stored> old_;
  std::deque<Entry> made_;                                // the entries made this run
  std::vector<std::pair<ListedFile, const Entry*>> new_;  // this run's: old_'s or made_'s
  bool changed_ = false;
};

// The annotations in the source files under roots, in list_files order (with a cache: unchanged files are not read)
std::vector<Annotation> parse_annotations(const std::vector<std::string>& roots, const std::string& module,
                                          std::vector<Ignored>* ignored, SourceCache* cache = nullptr);

}  // namespace verifier
