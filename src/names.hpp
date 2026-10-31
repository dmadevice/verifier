// C++ names: the map's symbols, and the keys names are paired by (qualified name, normalised parameter list, the
// function a local static belongs to), read from undecorated names and from source lines.
#pragma once
#include <deque>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "util.hpp"

namespace verifier {

extern const char* const SCALAR_DD;  // "`scalar deleting destructor'"

std::vector<std::pair<u64, std::string_view>> parse_map(std::string_view text);  // views of the text

std::string norm_name(const std::string& s);
std::string norm_params(const std::string& p);
long param_start(const std::string& s);  // -1 when none
std::string last_token(const std::string& head);
std::optional<std::string> definition_name(const std::string& line);
std::string static_owner(const std::string& und);
std::string signature(const std::string& und);
std::string qualified(const std::string& und);  // memoised
// Scanners for the patterns declarations and undecorated names are read by; each gives what the regular
// expression in its comment (names.cpp) gives, in linear time and without recursion.
std::optional<std::string> global_decl_name(std::string_view line);  // `int g_x[4] = ...` -> g_x
std::optional<std::string> class_decl_name(std::string_view line);   // `class __declspec(x) N::C : ...` -> N::C
std::string strip_declspec(const std::string& line);                 // each __declspec(...) -> " "
std::string fnptr_inner(const std::string& und);                     // `R (__cc*__cc f(p))(q)` -> `__cc f(p)`
// `dynamic initializer/atexit destructor for 'x''(void), with the owning function's text when x is a local static
bool dynamic_thunk(const std::string& und, std::optional<std::string>& owner, std::string& name);
// the last n components: the part after the n-th last "::" (occurrences found left to right, as lookups split
// names), or the whole name when it has fewer
std::string_view last_components(std::string_view q, int n);
size_t local_static_match(
    std::string_view dec);  // end of the local static prefix of a decorated name, 0 if it is not one

// pick_destructor(name, va, va is a vtable slot, has_code)
template <class HasCode>
std::string pick_destructor(const std::string& name, bool in_slot, HasCode has_code) {
  size_t p = name.rfind("::");
  std::string deleting = (p == std::string::npos ? name : name.substr(0, p)) + "::" + SCALAR_DD;
  // the deleting destructor of the destructor's class (the whole name when it has no "::")
  const std::string& plain = name;
  const std::string& first = in_slot ? deleting : plain;
  const std::string& second = in_slot ? plain : deleting;
  return (has_code(first) || !has_code(second)) ? first : second;
}

}  // namespace verifier
