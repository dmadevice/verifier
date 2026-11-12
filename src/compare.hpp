// Function comparison: code with its address fields resolved, referenced data and vtables, switch tables, unwind
// info, and C++ EH / SEH tables with their funclets. The pairing decisions come in through hooks (Pairing sets
// them; the tests set their own).
#pragma once
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "layouts.hpp"
#include "matching.hpp"
#include "names.hpp"
#include "pe.hpp"
#include "problem.hpp"
#include "x64.hpp"

namespace verifier {

// What a rebuilt address stands for: ('va', original VA) / ('const'|'str'|'td'|'ti'|'vbt'|'unresolved', name). Plain
// data: the name is a view of text that outlives the comparisons.
struct Key {
  enum Kind : u8 { VA, CONST, STR, TD, TI, VBT, UNRESOLVED, IMP } kind = UNRESOLVED;
  u64 va = 0;
  std::string_view name;
  const Import* imp = nullptr;  // IMP only (symbolised tokens): the image's entry
  static Key of_va(u64 v) {
    Key k;
    k.kind = VA;
    k.va = v;
    return k;
  }
  static Key named(Kind kd, std::string_view n) { return named_view(kd, keep_text(n)); }  // copies the name
  static Key named_view(Kind kd, std::string_view n) {
    Key k;
    k.kind = kd;
    k.name = n;
    return k;
  }  // n outlives the run
  bool is_va(u64 v) const { return kind == VA && va == v; }
  bool wide() const { return kind == STR && name_kind(name) == NameKind::WideString; }  // a wide string literal
  bool operator==(const Key& o) const {
    return kind == o.kind && va == o.va && name == o.name && (imp == o.imp || (imp && o.imp && *imp == *o.imp));
  }
  std::string text() const;  // what a problem message shows: hex(va) or the name
};


using NamePairs = std::vector<std::pair<Bytes, Bytes>>;  // (original decorated name, rebuilt one)

// a pair of functions to compare: the original's [ostart, oend) and the rebuild's [rstart, rend)
struct FnPair {
  u64 ostart, oend, rstart, rend;
};

i64 literal_size(const Image& img, u64 start, const Key& key);

// What a comparison asks beyond the two images: where the rebuild's symbols lie, what the original's names and data
// are, and what the pairing has decided. Pairing answers for a run; each default answers that nothing is known (no
// symbols, no names, nothing inferred), and the tests answer what each case sets.
class ComparerContext {
 public:
  virtual ~ComparerContext() = default;
  // the rebuild's symbols
  virtual bool symbol_start(u64 t) const { return false; }                     // a symbol starts at t
  virtual std::optional<u64> containing(u64 t) const { return std::nullopt; }  // the symbol t is in
  virtual u64 span(u64 t) const { return MAX_DATA_COMPARE; }                   // bytes from t to the next symbol
  // (local static, offset) when t is in a local static; the symbols a local static's address has (ICF folding)
  virtual std::optional<std::pair<u64, u64>> local_base(u64 t) const { return std::nullopt; }
  virtual int folded_locals(u64 base) const { return 1; }
  // the original addresses the names of a symbol of several names stand for
  virtual std::vector<u64> alternates(u64 t) const { return {}; }
  // the compiler constant or string literal t is in: (its start, its key)
  virtual std::optional<std::pair<u64, Key>> literal_at(u64 t) const { return std::nullopt; }
  // the original's objects and names
  virtual u64 orig_object_end(u64 t) const { return t; }    // where the object at t ends (t: unknown)
  virtual bool orig_padding(u64 t) const { return false; }  // t is alignment padding
  virtual bool orig_named(u64 t) const { return false; }    // t has a name of its own
  virtual std::vector<u64> orig_refs(u64 f) { return {}; }  // the addresses function f's code refers to, sorted
  // the pairing
  virtual bool annotated_between(u64 lo, u64 hi) const { return false; }  // an annotated original in (lo, hi]
  // the original address one past the data object before t ends at, when t starts a symbol
  virtual std::optional<u64> end_of_previous(u64 t) const { return std::nullopt; }
  // the original functions a local static's owners pair with (nullopt: unknown)
  virtual std::optional<std::vector<u64>> static_home(u64 base) const { return std::nullopt; }
  // an unresolved rebuilt function r_t that may stand for original function o_t (when its code compares equal): the
  // two functions to compare, or nullopt when it cannot
  virtual std::optional<FnPair> function_candidate(u64 o_t, u64 r_t) const { return std::nullopt; }
  // decoded functions kept for the run (nullptr: the Comparer decodes)
  virtual std::shared_ptr<const Code> orig_code(u64 start, u64 end) { return nullptr; }
  virtual std::shared_ptr<const Code> rebuilt_code(u64 start, u64 end) { return nullptr; }
};

// The comparison of a run's functions and data. A run explores its roots (the pairs it reports on), solves the
// matching, then judges each root against it (Matching says how):
//   cmp.explore(functions, data); cmp.solve(); ... cmp.judge_function(f) / cmp.judge_rodata(o, r) ...
// function(), rodata() and vtable() are the units the comparison is made of, compared the way the mode says.
class Comparer {
 public:
  // vtables (if given) and ctx (if given; else nothing is known) outlive the Comparer
  Comparer(const Image* O, const Image* R, std::function<Key(u64)> resolve,
           const std::map<u64, std::vector<u64>>* vtables = nullptr, NameOf names = nullptr,
           ComparerContext* ctx = nullptr);

  const Image *O, *R;
  std::function<Key(u64)> resolve;
  const std::map<u64, std::vector<u64>>& vtables;  // original vtable VA -> slot VAs
  NameOf names;                                    // original VA -> IDA name
  ComparerContext* ctx;                            // what is known beyond the two images (never null)
  Matching m;

  // the run: explore roots (any number of calls, each comparing the function candidates they register too), solve,
  // then judge each root
  void explore(const std::vector<FnPair>& functions, const std::vector<std::pair<u64, u64>>& data = {});
  void solve();
  Problems judge_function(const FnPair& f);
  std::optional<Problem> judge_rodata(u64 o_t, u64 r_t);
  // all three for these roots at once, each one's problems (the tests)
  std::vector<Problems> check(const std::vector<FnPair>& roots);
  Problems check(u64 ostart, u64 oend, u64 rstart, u64 rend) { return check({{ostart, oend, rstart, rend}})[0]; }

  // a function's decoded code: the context's (kept for the run), else decoded here
  std::shared_ptr<const Code> orig_code(u64 start, u64 end);
  std::shared_ptr<const Code> rebuilt_code(u64 start, u64 end);

  // the units
  Problems function(u64 ostart, u64 oend, u64 rstart, u64 rend);
  std::optional<Problem> rodata(u64 o_t, u64 r_t);
  std::optional<Problem> vtable(u64 o_vt, u64 r_vt);

  std::optional<Problem> ref(u64 o_t, u64 r_t, int access);
  // equal names, except that each build hash in a rebuilt name (anonymous namespace `?A0x...@`, lambda) stands
  // for one hash of the original's, the same one for the whole run
  bool same_names(const NamePairs& names);
  // the same values and structure (RTTI, a ThrowInfo's catchable types), then the same names
  bool same_signature(const Signature& a, const Signature& b);
  bool is_vtable_slot(u64 o_vt, u64 off) const;  // off: a slot of the original's vtable other than the first
  bool static_fits(u64 o_base, u64 base);
  bool refers_to(u64 f, u64 lo, u64 n);
  // `fi`: the FuncInfo pair of the function a funclet belongs to (compared there, not again for the funclet)
  Problems unwinds(u64 ostart, u64 oend, u64 rstart, u64 rend, std::optional<std::pair<u64, u64>> fi = std::nullopt);
  Problems unwind_info(u32 ou, u32 ru, u64 ostart, u64 oend, u64 rstart, u64 rend,
                       std::optional<std::pair<u64, u64>> fi = std::nullopt, int chain_depth = 0);

 private:
  using Kind = Matching::Kind;
  Problems function_body(const FnPair& f, std::optional<std::pair<u64, u64>> fi);
  Problems funclet(const FnPair& f, std::pair<u64, u64> fi);
  Problems code(u64 ostart, u64 oend, u64 rstart, u64 rend);
  std::optional<Problem> rodata_body(u64 o_t, u64 r_t);
  std::optional<Problem> vtable_body(u64 o_vt, u64 r_vt);
  // the guesses (Matching): whether r_t stands for o_t, as a function, vtable, read-only data or local static
  bool infer_function(u64 o_t, u64 r_t);
  bool infer_vtable(u64 o_vt, u64 r_vt);
  bool infer_data(u64 o_t, u64 r_t);
  bool bind_local(u64 o_t, u64 r_t);
  bool folded_extra(u64 base, u64 o_primary, u64 o_base);
  bool same_read(u64 o_t, u64 r_t, int access, u64 r_end, std::optional<bool> wide = std::nullopt);
  std::optional<Problem> accessed(u64 o_t, u64 r_t, int n);
  bool is_alternate(u64 o_t, u64 r_t);  // r_t's symbol is one of several at its address, one of them naming o_t
  std::optional<Problem> throw_info_cmp(u64 o_t, u64 r_t, std::string_view name);
  Problems handler_data(std::string_view handler, u64 od, u64 rd, u64 ostart, u64 oend, u64 rstart, u64 rend,
                        std::optional<std::pair<u64, u64>> fi);
  void explore_queued();
  friend class EHContext;
};

}  // namespace verifier
