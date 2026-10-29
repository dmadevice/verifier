// Source annotations: `// FUNCTION: <module> 0x<va>` and friends, read from the source trees.
#pragma once
#include <optional>
#include <set>
#include <string>
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
std::vector<Annotation> parse_annotations(const std::vector<std::string>& roots, const std::string& module,
                                          std::vector<Ignored>* ignored);
// exits (message on stderr, code 1) when two annotations claim one address without both saying FOLDED
void check_duplicates(const std::vector<Annotation>& anns);

}  // namespace verifier
