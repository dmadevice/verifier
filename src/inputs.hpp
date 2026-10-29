// The two sides' inputs: the original image with IDA's functions, vtables, data items and the library
// attribution; the rebuilt image with its map's symbol tables.
#pragma once
#include <functional>
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
  void load_items();
};

class Rebuilt;
struct Lookup { std::vector<u64> vas; std::string qname; size_t nhits; };

// Tests stand in for parts of a Rebuilt
struct RebuiltTestHooks {
  std::function<Lookup(const std::string&, const std::optional<std::string>&, bool)> lookup;
  std::function<u64(u64)> extent, span;
  std::function<std::optional<std::pair<u64, u64>>(u64)> local_base;
  std::function<std::string(std::string_view)> qualified;
};

class Rebuilt {
 public:
  Rebuilt(const std::string& path, const std::string& map_path, NameCache& names);
  Rebuilt() = default;   // fixtures: fill the fields
  RebuiltTestHooks test;
  Image img;
  // names are views of strings syms and the NameCache own (both outlive the tables)
  std::vector<std::pair<u64, std::string>> syms;
  std::unordered_map<u64, std::vector<std::string_view>> by_va;   // decorated names at an address, map order
  std::vector<u64> by_va_order;
  std::unordered_map<std::string_view, std::vector<u64>> qual_to_va;
  std::vector<std::string_view> qual_order;
  // (qualified name, address) -> its parameter lists there (sorted, distinct)
  std::map<std::pair<std::string_view, u64>, std::vector<std::string_view>> sigs_of;
  std::vector<u64> sym_vas;
  std::unordered_map<std::string_view, std::vector<std::string_view>> by_suffix;
  std::unordered_set<u64> local_statics;
  // local static VA -> the rebuilt functions it belongs to; nullopt: an owner without a symbol. Only statics
  // whose decorated name has the local static form have an entry (owners unknown for the others).
  std::map<u64, std::optional<std::set<u64>>> static_owner;

  std::string qualified(std::string_view dec) const {
    if (test.qualified) return test.qualified(dec);
    return names_ ? names_->info(dec).qualified : std::string(dec);
  }
  Lookup lookup(const std::string& key, const std::optional<std::string>& sig = std::nullopt, bool code = false) const;
  std::vector<std::string> overloads_of(const std::string& key) const;
  std::optional<u64> containing(u64 t) const;
  std::optional<u64> next_symbol(u64 t) const;
  u64 extent(u64 va) const;
  u64 span(u64 t) const;
  std::optional<std::pair<u64, u64>> local_base(u64 t) const;
  const std::optional<std::set<u64>>* owners_of(u64 base) const {
    auto it = static_owner.find(base);
    return it == static_owner.end() ? nullptr : &it->second;
  }

 private:
  NameCache* names_ = nullptr;
};

}  // namespace verifier
