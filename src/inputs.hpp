// The two sides' inputs: the original image with IDA's functions, vtables, data items and the library
// attribution; the rebuilt image with its map's symbol tables.
#pragma once
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "config.hpp"
#include "name_cache.hpp"
#include "names.hpp"
#include "pe.hpp"
#include "sha256.hpp"

namespace verifier {

constexpr u64 MAX_SYM_OFFSET = 0x10000;  // containing-symbol resolution: largest addend accepted

struct IdaFunction {
  u64 ea = 0, size = 0;
  std::string_view name;  // a view of text the Original keeps
  bool lib = false, thunk = false;
};

// IDA's functions, by address (a sorted vector)
class FunctionTable {
 public:
  const IdaFunction* find(u64 ea) const;
  bool contains(u64 ea) const { return find(ea) != nullptr; }
  const IdaFunction& at(u64 ea) const;       // throws std::out_of_range when there is none
  void set(const IdaFunction& f);            // adds it, or replaces the function at its address
  void assign(std::vector<IdaFunction> fs);  // in any order; of several at one address, the last
  size_t size() const { return fs_.size(); }
  const IdaFunction* begin() const { return fs_.data(); }
  const IdaFunction* end() const { return fs_.data() + fs_.size(); }

 private:
  std::vector<IdaFunction> fs_;
};

// The rebuilt map's symbols: the decorated names at each address, in map order (CSR: sorted addresses, each with
// a range of the names)
class Symbols {
 public:
  Symbols() = default;
  explicit Symbols(const std::vector<std::pair<u64, std::string_view>>& syms);  // (address, name) in map order
  std::span<const std::string_view> names(u64 va) const;                        // empty when no symbol is there
  bool contains(u64 va) const { return index(va) >= 0; }
  const std::vector<u64>& vas() const { return vas_; }          // sorted
  const std::vector<u64>& map_order() const { return order_; }  // the addresses as the map first has them

 private:
  std::vector<u64> vas_, order_;
  std::vector<u32> first_;  // vas_[i]'s names are names_[first_[i], first_[i + 1])
  std::vector<std::string_view> names_;
  long index(u64 va) const;
};

struct Linked {
  std::string lib, symbol;
  bool has_symbol = false;
};

class Original {
 public:
  // exits (code 1) when the original's SHA-256 is not the configured one, checked when the snapshot is made (a run
  // from the snapshot does not read the original); hash_file gives a file's (the caller's may remember the files it
  // has hashed)
  explicit Original(const Config& c, const std::function<std::string(const std::string&)>& hash_file = sha256_file);
  Original() = default;  // fixtures: fill the fields
  // the snapshot's key: the configured hash, and each input file's path, size and modification time. The snapshot (the
  // tables and the laid-out image, in the cache) is valid while they stay the same. "" when an input changed within
  // two seconds (two_seconds_ago): the snapshot is then neither used nor written
  static std::string snapshot_key(const Config& c);
  const std::string& cache_key() const { return cache_key_; }  // this run's snapshot_key ("" too for fixtures)
  std::string digest;
  Image img;
  FunctionTable functions;
  NameTable by_name;
  std::map<u64, std::vector<u64>> vtables;
  std::unordered_map<u64, Linked> linked;

  std::string_view ida_name(u64 va) const {  // "" for none
    const IdaFunction* f = functions.find(va);
    return f ? f->name : std::string_view();
  }
  u64 extent(u64 va) const;
  u64 object_end(u64 va) const;
  bool named_data(u64 va) const;
  bool in_padding(u64 va) const;

 private:
  const Config* config_ = nullptr;
  std::string cache_key_;
  std::shared_ptr<const MappedFile> snapshot_;  // the snapshot, when read from it: names and image are views of it
  std::deque<std::string> text_;                // or the names from the exports
  std::string_view keep(std::string s) { return text_.emplace_back(std::move(s)); }
  std::vector<u64> boundaries_, align_starts_, align_ends_;
  std::vector<u64> data_names_;  // sorted, distinct
  void load_exports();           // the tables from the text exports
  void load_items();
  bool load_snapshot(const std::string& path, const std::string& key);
  void save_snapshot(const std::string& path, const std::string& key) const;
};

struct Lookup {
  std::vector<u64> vas;
  std::string qname;
  size_t nhits;
};

// The rebuilt image and its symbols. The virtual methods are what tests stand in for (a subclass with its own
// answers, the tables filled by hand).
class Rebuilt {
 public:
  Rebuilt(const std::string& path, const std::string& map_path, NameCache& names);
  virtual ~Rebuilt() = default;
  Image img;
  Symbols symbols;  // names are views of strings the NameCache owns (it outlives the tables)
  std::unordered_set<u64> local_statics;
  // local static VA -> the rebuilt functions it belongs to; nullopt: an owner without a symbol. Only statics
  // whose decorated name has the local static form have an entry (owners unknown for the others).
  std::map<u64, std::optional<std::set<u64>>> static_owner;

  // a decorated name's qualified name (the name itself without a name cache)
  virtual std::string qualified(std::string_view dec) const {
    return names_ ? std::string(names_->info(dec).qualified) : std::string(dec);
  }
  // the rebuilt addresses an annotation's name (and parameter list) pairs with; code: executable ones only
  virtual Lookup lookup(const std::string& key, const std::optional<std::string>& sig = std::nullopt,
                        bool code = false) const;
  virtual u64 extent(u64 va) const;  // a function's end: its .pdata chain, else the next symbol (padding trimmed)
  virtual u64 span(u64 t) const;     // bytes to the next symbol, at most MAX_DATA_COMPARE
  // (local static, offset into it) for an address inside a local static
  virtual std::optional<std::pair<u64, u64>> local_base(u64 t) const;
  std::vector<std::string> overloads_of(const std::string& key) const;
  std::optional<u64> containing(u64 t) const;
  std::optional<u64> next_symbol(u64 t) const;
  const std::optional<std::set<u64>>* owners_of(u64 base) const {
    auto it = static_owner.find(base);
    return it == static_owner.end() ? nullptr : &it->second;
  }

 protected:
  Rebuilt() = default;  // tests: the tables filled by hand

 private:
  NameCache* names_ = nullptr;
  // what lookup() reads: this build's qualified names (NameCache ids), numbered in map order; by that number, the
  // address and parameter list of each symbol with that name, in map order (CSR); and the numbers by the ids of
  // their last one and two components (sorted: map order within each)
  struct QualSym {
    u64 va;
    std::string_view sig;
  };
  std::vector<u32> qual_ids_, qual_first_;
  std::vector<QualSym> qual_syms_;
  std::vector<std::pair<u32, u32>> by_last_[2];
  std::vector<u32> matching(
      const std::string& key) const;  // the numbers of the qualified names `key` names, in map order
  struct {
    std::string name;
    std::vector<u32> hits;
  } mutable last_;  // the last name lookup() matched, and its matches
};

}  // namespace verifier
