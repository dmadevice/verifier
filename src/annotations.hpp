// Source annotations: `// FUNCTION: <module> 0x<va>` and friends, read from the source trees.
#pragma once
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "util.hpp"

namespace verifier {

struct Annotation {
  std::string kind;       // FUNCTION STUB SYNTHETIC TEMPLATE LIBRARY GLOBAL VTABLE
  u64 va = 0;
  std::string name;
  std::set<std::string> flags;   // FOLDED, DTOR, SIG=<params>
  std::string path;
  int line = 0;
};

struct Ignored {
  std::string path;
  int line;
  std::string text;
};

bool is_counted(const std::string& kind);   // FUNCTION SYNTHETIC TEMPLATE
bool is_paired(const std::string& kind);    // counted + LIBRARY
std::optional<std::string> sig_flag(const std::set<std::string>& flags);

// Files in os.walk order (each directory's files sorted, subdirectories in the directory's own order).
std::vector<std::string> walk_files(const std::string& root);
std::vector<Annotation> parse_annotations(const std::vector<std::string>& roots, const std::string& module,
                                          std::vector<Ignored>* ignored);
// exits (message on stderr, code 1) when two annotations claim one address without both saying FOLDED
void check_duplicates(const std::vector<Annotation>& anns);

}  // namespace verifier
