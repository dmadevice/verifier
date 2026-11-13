// C++ names: the map's symbols, and the keys names are paired by (qualified name, normalised parameter list, the
// function a local static belongs to), as source lines spell them (the map's decorated names: demangle.hpp).
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

extern const char* const SCALAR_DD;

// What an MSVC decorated name says its object is, read from the name alone
enum class NameKind : u8 {
  Other,
  Constant,        // __real@<hex>, __xmm@<hex>, __mask@<hex>: a compiler constant
  String,          // ??_C@_0...: a narrow string literal
  WideString,      // ??_C@_1...: a wide string literal
  TypeDescriptor,  // ??_R0...: an RTTI type descriptor
  ThrowInfo,       // _TI...: a ThrowInfo
  VbTable,         // ??_8...: a virtual base table
  VfTable,         // ??_7...: a virtual function table
  LocalStatic,     // a function's local static or its guard (local_static_match)
};
NameKind name_kind(std::string_view decorated);
bool is_literal(NameKind k);  // a constant or string: compared by value, also at an offset into it
// the size of a compiler constant by its name (__real@ by its digits, __xmm@ and __mask@ 16), 0 for another name
i64 constant_size(std::string_view decorated);  // "`scalar deleting destructor'"

std::vector<std::pair<u64, std::string_view>> parse_map(std::string_view text);  // views of the text

std::string norm_name(const std::string& s);
bool is_norm_name(std::string_view s);  // norm_name leaves it as it is (it has no whitespace and no `__ptr64`)
std::string norm_params(const std::string& p);
long param_start(const std::string& s);  // -1 when none
std::string last_token(const std::string& head);
std::optional<std::string> definition_name(const std::string& line);
// Scanners for the patterns declarations are read by; each gives what the regular
// expression in its comment (names.cpp) gives, in linear time and without recursion.
std::optional<std::string> global_decl_name(std::string_view line);  // `int g_x[4] = ...` -> g_x
std::optional<std::string> class_decl_name(std::string_view line);   // `class __declspec(x) N::C : ...` -> N::C
std::string strip_declspec(const std::string& line);                 // each __declspec(...) -> " "
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
