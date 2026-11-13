// What each rebuilt address stands for in the original: annotated functions and data by name, other symbols by
// original name, compiler constants and literals by value, local statics as the votes before the comparison and the
// matching place them, and the unannotated functions that may stand for an original (function_candidate).
#pragma once
#include <deque>
#include <map>
#include <memory>
#include <optional>
#include <unordered_map>

#include "annotations.hpp"
#include "code_store.hpp"
#include "compare.hpp"
#include "inputs.hpp"

namespace verifier {

// the rebuilt symbols an annotation's name pairs with: Rebuilt::lookup by its key (VTABLE: its class's vftable)
Lookup lookup_annotation(const Rebuilt& reb, const Annotation& a, const std::optional<std::string>& sig, bool code);
// the parameter lists of the rebuilt functions an annotation's name names (Rebuilt::overloads_of by its key)
std::vector<std::string> overloads_of_annotation(const Rebuilt& reb, const Annotation& a);

class Pairing : public ComparerContext {
 public:
  Pairing(const Original& orig, const Rebuilt& reb, const std::vector<Annotation>& anns);
  const Original& orig;
  const Rebuilt& reb;
  std::optional<u64> named(
      std::string_view n) const;  // the original address the name has (the original's names, then vftables')
  std::optional<u64> orig_of(u64 rva) const;  // the original the last annotation naming `rva` gives
  std::vector<u64> annotated_o;               // sorted
  std::vector<u64> paired_o;                  // originals a non-STUB annotation pairs (sorted, distinct)

  // a compared annotation's rebuilt symbols and the overloads of its name, as pairing looked them up (nullptr for an
  // annotation pairing was not given)
  struct Paired {
    Lookup lookup;
    std::vector<std::string> overloads;
  };
  const Paired* paired(const Annotation& a) const;

  using Votes = std::map<u64, std::map<std::optional<u64>, u64>>;
  // the decoded functions the votes and the comparison share (without them each decodes its own)
  void use_caches(CodeCache& orig_cache, CodeCache& rebuilt_cache);
  // the local statics the votes place, fixed in the run's matching; resolve() then also answers from the statics the
  // matching places (it outlives the pairing's use)
  void prebind(Matching& m);
  // a compared pair's code is no longer needed (its comparison is kept): free it, if the caches hold it
  void release_code(const FnPair& f);
  Key resolve_symbol(u64 t) const;
  Key resolve(u64 t) const;
  // what the comparer asks (ComparerContext), answered from the two sides' tables and the pairing
  bool annotated_between(u64 lo, u64 hi) const override;
  std::optional<u64> end_of_previous(u64 t) const override;
  std::vector<u64> alternates(u64 t) const override;
  std::optional<std::pair<u64, Key>> literal_at(u64 t) const override;
  std::optional<FnPair> function_candidate(u64 o_t, u64 r_t) const override;
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
  std::shared_ptr<const Code> orig_code(u64 start, u64 end) override {
    return orig_cache_ ? orig_cache_->code(start, end) : nullptr;
  }
  std::shared_ptr<const Code> rebuilt_code(u64 start, u64 end) override {
    return rebuilt_cache_ ? rebuilt_cache_->code(start, end) : nullptr;
  }

  // local static votes: {static: {original start (nullopt: one that cannot be): furthest offset referenced}}
  std::vector<std::pair<u64, u64>> voting_pairs() const;
  Votes votes_of(u64 rva, u64 ova);
  std::map<u64, u64> decide_locals(const std::map<u64, Votes>& votes) const;

 private:
  void pair_vftables();
  std::shared_ptr<const Code> orig_function(u64 va);  // decoded through the cache, if any
  std::shared_ptr<const Code> rebuilt_function(u64 va);
  Key resolve_symbol_uncached(u64 t) const;

  // rebuilt vftable names of classes with several bases, not among the original's names: the original vftable each
  // stands for
  SvViewMap<u64> vftables_;
  std::unordered_map<std::string, Paired> paired_;  // by paired_key()
  // the same entries, by the address of the annotation each was made for
  U64Map<const std::pair<const std::string, Paired>*> paired_by_ann_;
  CodeCache *orig_cache_ = nullptr, *rebuilt_cache_ = nullptr;
  const Matching* matching_ = nullptr;
  std::vector<u64> named_;                         // original addresses with a name (sorted, distinct)
  std::vector<std::pair<u64, u64>> reb_to_orig_;   // (rebuilt, original of the last annotation naming it), sorted
  std::vector<std::pair<u64, u64>> reb_to_origs_;  // every (rebuilt, original) annotations name, sorted, distinct
  // what resolve() answers for an address, worked out once (all but the local statics the matching places, which
  // change as it goes)
  struct Resolved {
    Key symbol;                                // resolve_symbol's answer
    std::optional<std::pair<u64, u64>> local;  // a local static's (base, offset), when the symbol is unresolved
    Key rest;                                  // the answer when the matching places no local static there
  };
  const Resolved& resolved(u64 t) const;
  mutable U64Map<Resolved> resolved_;
  // the names made for addresses without one (kept for the pairing's life; a deque does not move them)
  mutable std::deque<std::string> texts_;
  std::string_view text(std::string s) const { return texts_.emplace_back(std::move(s)); }
  mutable std::unordered_map<u64, std::vector<u64>> alternates_;  // alternates' answers
  std::unordered_map<u64, std::vector<u64>> refs_of_;             // orig_refs' answers
};

}  // namespace verifier
