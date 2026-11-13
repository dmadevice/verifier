// What is read from the map's decorated names (demangle.hpp), kept in the cache directory between runs (see NameCache).
#pragma once
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "util.hpp"

namespace verifier {

// What the name tables need of each map symbol (NameCache), as the ids of its strings (NameCache::text): equal
// exactly when the strings are. The decorated name, qualified name, signature, owner, and the qualified name's last
// one and two components (last_components); failed: the name could not be demangled (its keys are the name itself).
struct NameIds {
  u32 decorated = 0, qualified = 0, signature = 0, owner = 0, last1 = 0, last2 = 0;
  bool failed = false;
};
struct NameInfo {  // the same as text (views of text the NameCache keeps for the run)
  std::string_view decorated, qualified, signature, owner;
};
class NameCache {
 public:
  // path "": no file, every name demangled
  NameCache(std::string path, std::string key);
  ~NameCache();
  // every name's ids (demangled for the names the file lacks), in the order given
  std::vector<NameIds> load(const std::vector<std::string_view>& decorated);
  NameInfo info(const NameIds& ids) const;
  NameInfo info(std::string_view d) const { return info(*find(d)); }  // a name load() was given
  std::string_view text(u32 id) const;
  std::optional<u32> id_of(std::string_view s) const;                 // the string's id, if it has one
  u32 string_count() const { return nstr_ + u32(new_text_.size()); }  // the ids are below it
  size_t new_names() const { return new_entries_.size(); }            // names load() demangled (the file lacks them)
  // the names of the last load() that could not be demangled, each once, in the order given
  const std::vector<std::string_view>& failed() const { return failed_; }
  // Writes the file when it is worth it, or with `force` whenever it lacks a name or holds them in another order:
  // this build's names in map order, then the file's other names in its order, as many as this build has (names of
  // other builds, kept so that runs on them find them). Worth it: no file was read, or load() demangled at least
  // SAVE_THRESHOLD names (fewer cost each run a millisecond or two: less than writing the file).
  void save(bool force = false);
  static constexpr size_t SAVE_THRESHOLD = 4096;

 private:
  std::string path_, key_;
  std::unique_ptr<const MappedFile> map_;  // the cache file, mapped and used in place
  std::string_view file_;
  const char* text_ = nullptr;
  const u32 *str_end_ = nullptr, *ent_ = nullptr, *eidx_ = nullptr, *sidx_ = nullptr;
  u32 nstr_ = 0, nent_ = 0, eslots_ = 0, sslots_ = 0;
  // added this run: strings (ids from nstr_ on, their text in chunks that never move) and entries
  std::vector<std::unique_ptr<char[]>> chunks_;
  char* chunk_at_ = nullptr;
  size_t chunk_left_ = 0;
  std::vector<std::string_view> new_text_;
  std::vector<u64> new_index_;     // open addressing: hash << 32 | string id - nstr_ + 1 (0: empty)
  std::vector<u32> new_entry_of_;  // by string id - nstr_: its entry in new_entries_ + 1 (0: none)
  std::vector<NameIds> new_entries_;
  std::vector<std::string_view> used_, failed_;  // this build's names; those that failed
  bool loaded_from_file_ = false;
  std::optional<NameIds> find(std::string_view d) const;
  long find_entry(std::string_view d) const;  // the file's entry for a name, -1 if none
  NameIds file_entry(u32 k) const;
  long find_new(std::string_view s, u32 h) const;  // a string added this run: its id, -1 if none
  u32 intern(std::string_view s);
  void reserve(size_t strings);  // room for this many strings added this run
};

}  // namespace verifier
