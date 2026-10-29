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

#include "pe.hpp"
#include "x64.hpp"

namespace verifier {

// text kept for the run, each distinct string once (names made while comparing)
std::string_view keep_text(std::string_view s);

// What a rebuilt address stands for: ('va', original VA) / ('const'|'str'|'td'|'ti'|'vbt'|'unresolved', name). Plain
// data: the name is a view of text that outlives the comparisons.
struct Key {
  enum Kind : u8 { VA, CONST, STR, TD, TI, VBT, UNRESOLVED, IMP } kind = UNRESOLVED;
  u64 va = 0;
  std::string_view name;
  const Import* imp = nullptr;   // IMP only (symbolised tokens): the image's entry
  static Key of_va(u64 v) { Key k; k.kind = VA; k.va = v; return k; }
  static Key named(Kind kd, std::string_view n) { return named_view(kd, keep_text(n)); }   // copies the name
  static Key named_view(Kind kd, std::string_view n) { Key k; k.kind = kd; k.name = n; return k; }   // n outlives the run
  bool is_va(u64 v) const { return kind == VA && va == v; }
  bool operator==(const Key& o) const {
    return kind == o.kind && va == o.va && name == o.name && (imp == o.imp || (imp && o.imp && *imp == *o.imp));
  }
  std::string text() const;   // what a problem message shows: hex(va) or the name
};

using Problem = std::pair<std::string, std::string>;   // (category, detail)
using Problems = std::vector<Problem>;

// -- journal: undo log of the pairing state while a pairing is only assumed ------------------------------------
class Journal {
 public:
  int active = 0;
  std::vector<std::function<void()>> log;
  bool speculate(const std::function<bool()>& attempt);
};

template <class K, class V, class H = std::hash<K>>
class JMap {
 public:
  explicit JMap(Journal* j = nullptr) : j_(j) {}
  void attach(Journal* j) { j_ = j; }
  bool contains(const K& k) const { return m_.count(k) != 0; }
  const V* find(const K& k) const { auto it = m_.find(k); return it == m_.end() ? nullptr : &it->second; }
  void set(const K& k, V v) {
    if (j_ && j_->active) {
      auto it = m_.find(k);
      if (it == m_.end()) j_->log.push_back([this, k] { m_.erase(k); });
      else { V old = it->second; j_->log.push_back([this, k, old] { m_[k] = old; }); }
    }
    m_[k] = std::move(v);
  }
  const std::unordered_map<K, V, H>& items() const { return m_; }
  size_t size() const { return m_.size(); }

 private:
  Journal* j_;
  std::unordered_map<K, V, H> m_;
};

struct PairHash {
  size_t operator()(const std::pair<u64, u64>& p) const { return std::hash<u64>()(p.first * 0x9E3779B97F4A7C15ull ^ p.second); }
};

using NamePairs = std::vector<std::pair<Bytes, Bytes>>;   // (original decorated name, rebuilt one)

i64 const_size(std::string_view name);
i64 literal_size(const Image& img, u64 start, const Key& key);

class Comparer {
 public:
  // vtables and names (if given) outlive the Comparer
  Comparer(const Image* O, const Image* R, std::function<Key(u64)> resolve,
           const std::map<u64, std::vector<u64>>* vtables = nullptr, const NameMap* names = nullptr);

  const Image *O, *R;
  std::function<Key(u64)> resolve;
  const std::map<u64, std::vector<u64>>& vtables;   // original vtable VA -> slot VAs
  const NameMap& names;                              // original VA -> IDA name

  Journal journal;
  // results kept for the run (journaled): functions, read-only data and vtables by (original, rebuilt) address;
  // FuncInfo pairs both ways
  JMap<std::pair<u64, u64>, Problems, PairHash> memo_fn{&journal};
  JMap<std::pair<u64, u64>, std::optional<Problem>, PairHash> memo_ro{&journal};
  JMap<std::pair<u64, u64>, std::optional<Problem>, PairHash> memo_vt{&journal};
  JMap<u64, u64> memo_fi{&journal}, memo_fir{&journal};
  JMap<u64, u64> bound{&journal}, bound_o{&journal};
  JMap<u64, u64> data_r{&journal}, data_o{&journal};
  JMap<std::string, std::string> hash_r{&journal}, hash_o{&journal};
  JMap<u64, u64> vt_r{&journal}, vt_o{&journal};

  // hooks
  std::function<std::vector<u64>(u64)> alternates = [](u64) { return std::vector<u64>(); };
  std::function<std::optional<std::pair<u64, u64>>(u64)> local_base = [](u64) { return std::nullopt; };
  std::function<std::optional<std::vector<u64>>(u64)> static_home = [](u64) { return std::nullopt; };
  std::function<u64(u64)> orig_object_end = [](u64 t) { return t; };
  std::function<bool(u64)> orig_padding = [](u64) { return false; };
  std::function<bool(u64, u64)> annotated_between = [](u64, u64) { return false; };
  std::function<std::vector<u64>(u64)> orig_refs = [](u64) { return std::vector<u64>(); };
  std::function<int(u64)> folded_locals = [](u64) { return 1; };
  std::function<std::optional<u64>(u64)> containing = [](u64) { return std::nullopt; };
  std::function<std::optional<u64>(u64)> end_of_previous = [](u64) { return std::nullopt; };
  std::function<bool(u64)> orig_named = [](u64) { return false; };
  std::function<std::optional<std::pair<u64, Key>>(u64)> literal_at = [](u64) { return std::nullopt; };
  std::function<std::shared_ptr<const Code>(u64, u64)> orig_code;
  std::function<std::shared_ptr<const Code>(u64, u64)> rebuilt_code;
  std::function<bool(u64, u64)> infer = [](u64, u64) { return false; };
  std::function<bool(u64)> symbol_start = [](u64) { return false; };
  std::function<u64(u64)> span = [](u64) { return MAX_DATA_COMPARE; };

  Problems function(u64 ostart, u64 oend, u64 rstart, u64 rend, int depth = 0);
  std::optional<Problem> ref(u64 o_t, u64 r_t, int access);
  std::optional<Problem> rodata(u64 o_t, u64 r_t);
  std::optional<Problem> vtable(u64 o_vt, u64 r_vt);
  // equal names, except that each build hash in a rebuilt name (anonymous namespace `?A0x...@`, lambda) stands
  // for one hash of the original's, the same one for the whole run
  bool same_names(const NamePairs& names);
  bool same_rtti(const Rtti& a, const Rtti& b);                    // offsets, hierarchy, then the names
  bool same_catchables(const ThrowInfoSig& a, const ThrowInfoSig& b);
  bool infer_data(u64 o_t, u64 r_t);
  bool infer_vtable(u64 o_vt, u64 r_vt);
  std::optional<Key> bind_local(u64 o_t, u64 r_t);
  bool static_fits(u64 o_base, u64 base);
  bool static_overlaps(u64 o_base, u64 o_t, u64 base);
  bool refers_to(u64 f, u64 lo, u64 n);
  Problems unwinds(u64 ostart, u64 oend, u64 rstart, u64 rend, int depth = 0);
  Problems unwind_info(u32 ou, u32 ru, u64 ostart, u64 oend, u64 rstart, u64 rend, int depth, int chain_depth = 0);

 private:
  Problems code(u64 ostart, u64 oend, u64 rstart, u64 rend);
  bool same_read(u64 o_t, u64 r_t, int access, u64 r_end, std::optional<bool> wide = std::nullopt);
  std::optional<Problem> accessed(u64 o_t, u64 r_t, int n);
  bool is_alternate(u64 o_t, u64 r_t);   // r_t's symbol is one of several at its address, one of them naming o_t
  std::optional<Problem> throw_info_cmp(u64 o_t, u64 r_t, std::string_view name);
  Problems handler_data(std::string_view handler, u64 od, u64 rd, u64 ostart, u64 oend, u64 rstart, u64 rend, int depth);
  friend class EHContext;
};

}  // namespace verifier
