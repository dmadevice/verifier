// The undecorated names, and what is read from them, kept in the cache directory between runs (see NameCache).
#pragma once
#include <deque>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "util.hpp"

namespace verifier {

// What the name tables need of each map symbol (NameCache), as the ids of its strings (NameCache::text): equal
// exactly when the strings are. The decorated and undecorated name (if any), qualified name, signature, owner, and
// the qualified name's last one and two components (last_components).
struct NameIds {
  u32 decorated = 0, und = 0, qualified = 0, signature = 0, owner = 0, last1 = 0, last2 = 0;
  bool has_und = false;
};
struct NameInfo {  // the same as text (views of text the NameCache keeps for the run)
  bool has_und = false;
  std::string_view decorated, und, qualified, signature, owner;
};
class NameCache {
 public:
  NameCache(std::string path, std::string key, std::string undname);
  // every name's ids (undname for the new ones), in the order given
  std::vector<NameIds> load(const std::vector<std::string_view>& decorated);
  NameInfo info(const NameIds& ids) const;
  NameInfo info(std::string_view d) const { return info(*find(d)); }  // a name load() was given
  std::string_view text(u32 id) const;
  std::optional<u32> id_of(std::string_view s) const;                 // the string's id, if it has one
  u32 string_count() const { return nstr_ + u32(new_text_.size()); }  // the ids are below it
  bool has_new() const { return !new_entries_.empty(); }              // load() ran undname for names the file lacks
  // writes the file: this build's names in map order, then the file's other names in its order, as many as this build
  // has (names of other builds, kept so that runs on them do not run undname again). Nothing is written when the file
  // already starts with these names and holds no more than that.
  void save();

 private:
  std::string path_, key_, undname_;
  std::unique_ptr<const MappedFile> map_;  // the cache file, mapped and used in place
  std::string_view file_;
  const char* text_ = nullptr;
  const u32 *str_end_ = nullptr, *ent_ = nullptr, *eidx_ = nullptr, *sidx_ = nullptr;
  u32 nstr_ = 0, nent_ = 0, eslots_ = 0, sslots_ = 0;
  // added this run: strings (ids from nstr_ on) and entries
  std::deque<std::string> owned_;
  std::vector<std::string_view> new_text_;
  std::unordered_map<std::string_view, u32, SvHash> new_ids_;
  std::unordered_map<std::string_view, NameIds, SvHash> new_entries_;
  std::vector<std::string_view> used_;  // this build's names
  bool loaded_from_file_ = false;
  std::optional<NameIds> find(std::string_view d) const;
  long find_entry(std::string_view d) const;  // the file's entry for a name, -1 if none
  NameIds file_entry(u32 k) const;
  u32 intern(std::string s);
};

}  // namespace verifier
