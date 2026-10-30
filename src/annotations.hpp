// Source annotations: `// FUNCTION: <module> 0x<va>` and friends, read from the source trees.
#pragma once
#include <functional>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "util.hpp"

namespace verifier {

struct AnnotationFlags {
  bool folded = false;   // FOLDED: identical-code folding gave several functions the address
  bool dtor = false;     // the definition is a destructor
  std::string sig;       // the parameter list it pairs with (normalised; "" for any)
};

struct Annotation {
  std::string kind;       // FUNCTION STUB SYNTHETIC TEMPLATE LIBRARY GLOBAL VTABLE
  u64 va = 0;
  std::string name;
  AnnotationFlags flags;
  std::string_view path;  // text kept for the run (keep_text)
  int line = 0;
};

struct Ignored {
  std::string path;
  int line;
  std::string text;
};

bool is_counted(const std::string& kind);   // FUNCTION SYNTHETIC TEMPLATE
bool is_paired(const std::string& kind);    // counted + LIBRARY
std::optional<std::string> sig_flag(const AnnotationFlags& flags);   // the parameter list, if any

// The files under root: each directory's files (sorted by name), then its subdirectories (sorted by name).
std::vector<std::string> walk_files(const std::string& root);
// The same files with their sizes and modification times (on Windows from the directory listing, without opening
// each file)
struct ListedFile {
  std::string path;
  u64 size = 0;
  i64 time = 0;   // the file clock's ticks
};
std::vector<ListedFile> list_files(const std::string& root);
// The annotations in the files under roots. `seen`, when given, gets every file as list_files gives it and its
// contents, in walk_files order, the files that cannot hold an annotation included.
std::vector<Annotation> parse_annotations(const std::vector<std::string>& roots, const std::string& module,
                                          std::vector<Ignored>* ignored,
                                          const std::function<void(const ListedFile&, std::string_view)>& seen = {});
// exits (message on stderr, code 1) when two annotations claim one address without both saying FOLDED
void check_duplicates(const std::vector<Annotation>& anns);

}  // namespace verifier
