// C++ names: undecorating map symbols (undname.exe), and the keys names are paired by (qualified name,
// normalised parameter list, the function a local static belongs to).
#pragma once
#include <deque>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "util.hpp"

namespace verifier {

extern const char* const SCALAR_DD;   // "`scalar deleting destructor'"

std::vector<std::pair<u64, std::string>> parse_map(const std::string& path);

std::string norm_name(const std::string& s);
std::string norm_params(const std::string& p);
long param_start(const std::string& s);              // -1 when none
std::string last_token(const std::string& head);
std::optional<std::string> definition_name(const std::string& line);
std::string static_owner(const std::string& und);
std::string signature(const std::string& und);
std::string qualified(const std::string& und);        // memoised
size_t local_static_match(const std::string& dec);    // end of the local static prefix of a decorated name, 0 if it is not one

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

// What the name tables need of each map symbol (NameCache): undecorated (if any), qualified, signature, owner
// (views of text the NameCache keeps for the run)
struct NameInfo {
  bool has_und = false;
  std::string_view und, qualified, signature, owner;
};
class NameCache {
 public:
  NameCache(std::string path, std::string key, std::string undname);
  // every name's NameInfo (undname for the new ones), in the order given
  std::vector<const NameInfo*> load(const std::vector<std::string_view>& decorated);
  const NameInfo& info(std::string_view d) const { return entries_.find(d)->second; }
  void save();

 private:
  std::string path_, key_, undname_;
  std::string file_;                // the cache file's text: the entries read from it are views of it
  std::deque<std::string> owned_;   // the text of the entries added this run
  std::unordered_map<std::string_view, NameInfo, SvHash> entries_;
  std::vector<std::string_view> used_;   // this build's names (entries_' keys)
  std::string_view own(std::string s) { return owned_.emplace_back(std::move(s)); }
  bool loaded_from_file_ = false;
  size_t stored_ = 0;
};

}  // namespace verifier
