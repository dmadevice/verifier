// Source annotations: `// FUNCTION: <module> 0x<va>` and friends, read from the source trees.
#pragma once
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "util.hpp"

namespace verifier {

// What an annotation says its definition is
enum class Kind : u8 { Function, Stub, Synthetic, Template, Library, Global, Vtable };
std::string_view kind_name(Kind k);                    // as written in source: FUNCTION, STUB, ...
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
};

struct Ignored {
  std::string path;
  int line;
  std::string text;
};

std::optional<std::string> sig_flag(const AnnotationFlags& flags);  // the parameter list, if any

// The files under root: each directory's files (sorted by name), then its subdirectories (sorted by name)
std::vector<std::string> list_files(const std::string& root);

// The annotations in the source files under roots, in list_files order
std::vector<Annotation> parse_annotations(const std::vector<std::string>& roots, const std::string& module,
                                          std::vector<Ignored>* ignored);

}  // namespace verifier
