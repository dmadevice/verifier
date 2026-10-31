// What each rebuilt address stands for in the original: annotated functions and data by name, other symbols by
// original name, compiler constants and literals by value, local statics as comparisons (and the votes before
// them) pair them, and unannotated functions whose code compares equal (infer).
#pragma once
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <unordered_map>

#include "annotations.hpp"
#include "code_store.hpp"
#include "compare.hpp"
#include "inputs.hpp"

namespace verifier {

class Pairing : public ComparerContext {
 public:
  Pairing(const Original& orig, const Rebuilt& reb, const std::vector<Annotation>& anns);
  // the same name pairing as `base`, without its comparer or anything learnt while comparing (mutation probes)
  Pairing(const Pairing& base);
  const Original& orig;
  const Rebuilt& reb;
  std::unique_ptr<Comparer> cmp;
  std::optional<u64> named(std::string_view n) const;   // the original address the name has (the original's names, then vftables')
  std::unordered_map<u64, u64> reb_to_orig;
  std::unordered_map<u64, std::set<u64>> reb_to_origs;
  std::vector<u64> annotated_o;   // sorted

  std::set<u64> paired_o;   // originals a non-STUB annotation pairs

  // a compared annotation's rebuilt symbols and the overloads of its name, as pairing looked them up (nullptr for an
  // annotation pairing was not given)
  struct Paired { Lookup lookup; std::vector<std::string> overloads; };
  const Paired* paired(const Annotation& a) const;

  using Votes = std::map<u64, std::map<std::optional<u64>, u64>>;
  // votes_fn: the local static votes to decide from instead of computing every voter's (mutation probes)
  Comparer& comparer(CodeCache& orig_cache, CodeCache& rebuilt_cache,
                     const std::function<std::map<u64, Votes>(Pairing&)>& votes_fn = nullptr);
  void use(std::unique_ptr<Comparer> c);   // fixtures: a Comparer with hooks of their own
  // a compared pair's code is no longer needed (its comparison is kept): free it, if the caches hold it
  void release_code(u64 ostart, u64 oend, u64 rstart, u64 rend);
  Key resolve_symbol(u64 t) const;
  Key resolve(u64 t) const;
  // what the comparer asks (ComparerContext), answered from the two sides' tables and the pairing
  bool annotated_between(u64 lo, u64 hi) const override;
  std::optional<u64> end_of_previous(u64 t) const override;
  std::vector<u64> alternates(u64 t) const override;
  std::optional<std::pair<u64, Key>> literal_at(u64 t) const override;
  bool infer(u64 o_t, u64 r_t) override;
  std::optional<std::vector<u64>> static_home(u64 base) const override;
  std::vector<u64> orig_refs(u64 f) override;
  bool symbol_start(u64 t) const override { return reb.symbols.contains(t); }
  std::optional<u64> containing(u64 t) const override { return reb.containing(t); }
  u64 span(u64 t) const override { return reb.span(t); }
  std::optional<std::pair<u64, u64>> local_base(u64 t) const override { return reb.local_base(t); }
  int folded_locals(u64 base) const override { return int(reb.symbols.names(base).size()); }
  u64 orig_object_end(u64 t) const override { return orig.object_end(t); }
  bool orig_padding(u64 t) const override { return orig.in_padding(t); }
  bool orig_named(u64 t) const override;
  std::shared_ptr<const Code> orig_code(u64 start, u64 end) override { return orig_cache_ ? orig_cache_->code(start, end) : nullptr; }
  std::shared_ptr<const Code> rebuilt_code(u64 start, u64 end) override {
    return rebuilt_cache_ ? rebuilt_cache_->code(start, end) : nullptr;
  }

  // local static votes: {static: {original start (nullopt: one that cannot be): furthest offset referenced}}
  std::vector<std::pair<u64, u64>> voting_pairs() const;
  Votes votes_of(u64 rva, u64 ova);
  std::map<u64, u64> decide_locals(const std::map<u64, Votes>& votes) const;

 private:
  void pair_vftables();
  SvViewMap<u64> vftables_;
  std::unordered_map<std::string, Paired> paired_;   // by paired_key()   // rebuilt vftable names of classes with several bases, not among the original's names
  void prebind_locals(const std::function<std::map<u64, Votes>(Pairing&)>& votes_fn);
  CodeCache *orig_cache_ = nullptr, *rebuilt_cache_ = nullptr;
  std::vector<u64> named_;   // original addresses with a name (sorted, distinct)
  JMap<std::pair<u64, u64>, bool, PairHash> inferred_;
  JMap<u64, u64> inferred_r_;
  Key resolve_symbol_uncached(u64 t) const;
  mutable std::unordered_map<u64, Key> resolved_;   // resolve_symbol's answers
  int infer_depth_ = 0;
  std::unordered_map<u64, std::vector<u64>> refs_of_;
};

}  // namespace verifier
