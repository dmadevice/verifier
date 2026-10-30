// C++ names: undecorating map symbols (undname.exe), and the keys names are paired by (qualified name,
// normalised parameter list, the function a local static belongs to).
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

extern const char* const SCALAR_DD;   // "`scalar deleting destructor'"

std::vector<std::pair<u64, std::string_view>> parse_map(std::string_view text);   // views of the text

std::string norm_name(const std::string& s);
std::string norm_params(const std::string& p);
long param_start(const std::string& s);              // -1 when none
std::string last_token(const std::string& head);
std::optional<std::string> definition_name(const std::string& line);
std::string static_owner(const std::string& und);
std::string signature(const std::string& und);
std::string qualified(const std::string& und);        // memoised
// Scanners for the patterns declarations and undecorated names are read by; each gives what the regular
// expression in its comment (names.cpp) gives, in linear time and without recursion.
std::optional<std::string> global_decl_name(std::string_view line);   // `int g_x[4] = ...` -> g_x
std::optional<std::string> class_decl_name(std::string_view line);    // `class __declspec(x) N::C : ...` -> N::C
std::string strip_declspec(const std::string& line);                  // each __declspec(...) -> " "
std::string fnptr_inner(const std::string& und);                      // `R (__cc*__cc f(p))(q)` -> `__cc f(p)`
// `dynamic initializer/atexit destructor for 'x''(void), with the owning function's text when x is a local static
bool dynamic_thunk(const std::string& und, std::optional<std::string>& owner, std::string& name);
// the last n components: the part after the n-th last "::" (occurrences found left to right, as lookups split
// names), or the whole name when it has fewer
std::string_view last_components(std::string_view q, int n);
size_t local_static_match(std::string_view dec);    // end of the local static prefix of a decorated name, 0 if it is not one

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

// {decorated: undecorated} for the names starting with '?', by running `undname` in batches, one after another
std::unordered_map<std::string, std::string> undecorate(const std::vector<std::string>& names, const std::string& undname);

// What the name tables need of each map symbol (NameCache), as the ids of its strings (NameCache::text): equal
// exactly when the strings are. The decorated and undecorated name (if any), qualified name, signature, owner, and
// the qualified name's last one and two components (last_components).
struct NameIds {
  u32 decorated = 0, und = 0, qualified = 0, signature = 0, owner = 0, last1 = 0, last2 = 0;
  bool has_und = false;
};
struct NameInfo {   // the same as text (views of text the NameCache keeps for the run)
  bool has_und = false;
  std::string_view decorated, und, qualified, signature, owner;
};
class NameCache {
 public:
  NameCache(std::string path, std::string key, std::string undname);
  // every name's ids (undname for the new ones), in the order given
  std::vector<NameIds> load(const std::vector<std::string_view>& decorated);
  NameInfo info(const NameIds& ids) const;
  NameInfo info(std::string_view d) const { return info(*find(d)); }   // a name load() was given
  std::string_view text(u32 id) const;
  std::optional<u32> id_of(std::string_view s) const;   // the string's id, if it has one
  u32 string_count() const { return nstr_ + u32(new_text_.size()); }   // the ids are below it
  void save();

 private:
  std::string path_, key_, undname_;
  std::shared_ptr<const MappedFile> map_;   // the cache file, mapped and used in place
  std::string_view file_;
  const char* text_ = nullptr;
  const u32 *str_end_ = nullptr, *ent_ = nullptr, *eidx_ = nullptr, *sidx_ = nullptr;
  u32 nstr_ = 0, nent_ = 0, eslots_ = 0, sslots_ = 0;
  // added this run: strings (ids from nstr_ on) and entries
  std::deque<std::string> owned_;
  std::vector<std::string_view> new_text_;
  std::unordered_map<std::string_view, u32, SvHash> new_ids_;
  std::unordered_map<std::string_view, NameIds, SvHash> new_entries_;
  std::vector<std::string_view> used_;   // this build's names
  bool loaded_from_file_ = false;
  std::optional<NameIds> find(std::string_view d) const;
  long find_entry(std::string_view d) const;   // the file's entry for a name, -1 if none
  NameIds file_entry(u32 k) const;
  u32 intern(std::string s);
};

}  // namespace verifier
