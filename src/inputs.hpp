// The two sides' inputs: the original image with IDA's functions, vtables, data items and the library
// attribution; the rebuilt image with its map's symbol tables.
#pragma once
#include <map>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "config.hpp"
#include "names.hpp"
#include "pe.hpp"

namespace verifier {

constexpr u64 MAX_SYM_OFFSET = 0x10000;   // containing-symbol resolution: largest addend accepted

struct IdaFunction {
  u64 ea = 0, size = 0;
  std::string name;
  bool lib = false, thunk = false;
};

struct Linked {
  std::string lib, symbol;
  bool has_symbol = false;
};

class Original {
 public:
  explicit Original(const Config& c);   // exits (code 1) when the original's SHA-256 is not the configured one
  Original() = default;                 // fixtures: fill the fields
  std::string digest;
  Image img;
  std::unordered_map<u64, IdaFunction> functions;
  std::vector<u64> function_order;                 // in the order of the export file
  std::unordered_map<u64, std::string> ida_names;
  SvMap<u64> by_name;
  std::map<u64, std::vector<u64>> vtables;
  std::unordered_map<u64, Linked> linked;

  u64 extent(u64 va) const;
  u64 object_end(u64 va) const;
  bool named_data(u64 va) const;
  bool in_padding(u64 va) const;

 private:
  const Config* config_ = nullptr;
  std::vector<u64> boundaries_, align_starts_, align_ends_;
  std::unordered_set<u64> data_names_;
  void load_exports();   // the tables from the text exports
  void load_items();
  // the tables as a binary file in the cache, valid while every input file keeps its size and modification time
  static std::string snapshot_key(const Config& c);
  bool load_snapshot(const std::string& path, const std::string& key);
  void save_snapshot(const std::string& path, const std::string& key) const;
};

struct Lookup { std::vector<u64> vas; std::string qname; size_t nhits; };

// The rebuilt image and its symbols. The virtual methods are what tests stand in for (a subclass with its own
// answers, the tables filled by hand).
class Rebuilt {
 public:
  Rebuilt(const std::string& path, const std::string& map_path, NameCache& names);
  virtual ~Rebuilt() = default;
  Image img;
  // names are views of the map's text and of strings the NameCache owns (both outlive the tables)
  std::string map_text;
  std::vector<std::pair<u64, std::string_view>> syms;
  std::unordered_map<u64, std::vector<std::string_view>> by_va;   // decorated names at an address, map order
  std::vector<u64> by_va_order;
  std::unordered_map<std::string_view, std::vector<u64>, SvHash> qual_to_va;
  std::vector<std::string_view> qual_order;
  // (qualified name, address) -> its parameter lists there (sorted, distinct)
  struct NameVaHash {
    size_t operator()(const std::pair<std::string_view, u64>& k) const {
      return std::hash<std::string_view>()(k.first) ^ (k.second * 0x9E3779B97F4A7C15ull);
    }
  };
  std::unordered_map<std::pair<std::string_view, u64>, std::vector<std::string_view>, NameVaHash> sigs_of;
  std::vector<u64> sym_vas;
  std::unordered_map<std::string_view, std::vector<std::string_view>, SvHash> by_suffix;
  std::unordered_set<u64> local_statics;
  // local static VA -> the rebuilt functions it belongs to; nullopt: an owner without a symbol. Only statics
  // whose decorated name has the local static form have an entry (owners unknown for the others).
  std::map<u64, std::optional<std::set<u64>>> static_owner;

  // a decorated name's qualified name (the name itself without a name cache)
  virtual std::string qualified(std::string_view dec) const { return names_ ? std::string(names_->info(dec).qualified) : std::string(dec); }
  // the rebuilt addresses an annotation's name (and parameter list) pairs with; code: executable ones only
  virtual Lookup lookup(const std::string& key, const std::optional<std::string>& sig = std::nullopt, bool code = false) const;
  virtual u64 extent(u64 va) const;   // a function's end: its .pdata chain, else the next symbol (padding trimmed)
  virtual u64 span(u64 t) const;      // bytes to the next symbol, at most MAX_DATA_COMPARE
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
  Rebuilt() = default;   // tests: the tables filled by hand

 private:
  NameCache* names_ = nullptr;
};

}  // namespace verifier
