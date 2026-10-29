#include "pairing.hpp"

#include <algorithm>
#include <cctype>

namespace verifier {

std::shared_ptr<const Code> CodeCache::code(u64 start, u64 end) {
  auto it = live_.find({start, end});
  if (it != live_.end()) return it->second;
  return live_.emplace(std::make_pair(start, end), std::make_shared<const Code>(*img_, start, end)).first->second;
}

namespace {

bool any_prefix(std::string_view n, std::initializer_list<const char*> ps) {
  for (auto p : ps) if (starts_with(n, p)) return true;
  return false;
}

bool is_const_name(std::string_view n) { return any_prefix(n, {"__real@", "__xmm@", "__mask@"}); }

// an original vftable name of a class with several bases, `??_7<class>@@6B@` or `??_7<class>@@6B@_<n>`: the part up to
// `@@6B`, or "" for any other name
std::string orig_mi_vftable(std::string_view n) {
  if (!starts_with(n, "??_7")) return "";
  auto try_k = [&](size_t k) -> std::string {
    if (k < 4 + 4 || n.compare(k - 4, 4, "@@6B") != 0) return "";
    return std::string(n.substr(0, k));
  };
  if (ends_with(n, "@")) {
    auto g = try_k(n.size() - 1);
    if (!g.empty()) return g;
  }
  size_t e = n.size();
  size_t d = e;
  while (d > 0 && std::isdigit(static_cast<unsigned char>(n[d - 1]))) --d;
  if (d < e && d >= 2 && n[d - 1] == '_' && n[d - 2] == '@') return try_k(d - 2);
  return "";
}

// a rebuilt one, `??_7<class>@@6B<base>@@`: the part up to the last `@@6B` that leaves a base name, or ""
std::string reb_mi_vftable(std::string_view n) {
  if (!starts_with(n, "??_7") || !ends_with(n, "@@") || n.size() < 4 + 4 + 3) return "";
  for (size_t k = n.size() - 3; k >= 8; --k)   // k: end of group 1; n[k : len-2] is .+ (non-empty)
    if (n.compare(k - 4, 4, "@@6B") == 0) return std::string(n.substr(0, k));
  return "";
}

}  // namespace

Pairing::Pairing(const Original& o, const Rebuilt& r, const std::vector<Annotation>& anns) : orig(o), reb(r) {
  by_name = orig.by_name;
  pair_vftables();
  for (auto& a : anns) {
    std::string key = a.kind == "VTABLE" ? a.name + "::`vftable'" : a.name;
    for (u64 rva : reb.lookup(key, sig_flag(a.flags), is_paired(a.kind)).vas) {
      reb_to_orig[rva] = a.va;
      reb_to_origs[rva].insert(a.va);
      if (a.kind != "STUB") paired_o.insert(a.va);
    }
  }
  std::set<u64> ao;
  for (auto& [rva, va] : reb_to_orig) ao.insert(va);
  annotated_o.assign(ao.begin(), ao.end());
}

Pairing::Pairing(const Pairing& b)
    : orig(b.orig), reb(b.reb), by_name(b.by_name), reb_to_orig(b.reb_to_orig), reb_to_origs(b.reb_to_origs),
      annotated_o(b.annotated_o), paired_o(b.paired_o) {}

void Pairing::pair_vftables() {
  const Image &O = orig.img, &R = reb.img;
  std::unordered_map<std::string, std::vector<u64>> mi;
  for (auto& [n, ea] : by_name) {
    auto g = orig_mi_vftable(n);
    if (!g.empty()) mi[g].push_back(ea);
  }
  for (u64 va : reb.by_va_order) {
    for (auto& n : reb.by_va.at(va)) {
      auto g = reb_mi_vftable(n);
      if (g.empty() || by_name.count(n) || !mi.count(g)) continue;
      u64 r_col = R.u64_at(va - 8);
      if (!R.flags(r_col)) continue;
      Bytes offsets(R.bytes(r_col + 4, 8));
      std::vector<u64> hits;
      for (u64 ea : mi[g]) {
        u64 col = O.u64_at(ea - 8);
        if (O.flags(col) && Bytes(O.bytes(col + 4, 8)) == offsets) hits.push_back(ea);
      }
      if (hits.size() == 1) by_name[n] = hits[0];
    }
  }
}

void Pairing::use(std::unique_ptr<Comparer> c) {
  cmp = std::move(c);
  inferred_.attach(&cmp->journal);
  inferred_r_.attach(&cmp->journal);
}

Comparer& Pairing::comparer(CodeCache& oc, CodeCache& rc, const std::function<std::map<u64, Votes>(Pairing&)>& votes_fn) {
  use(std::make_unique<Comparer>(&orig.img, &reb.img, [this](u64 t) { return resolve(t); }, &orig.vtables, &orig.ida_names));
  Comparer& c = *cmp;
  orig_cache_ = &oc;
  rebuilt_cache_ = &rc;
  c.orig_code = [&oc](u64 s, u64 e) { return oc.code(s, e); };
  c.rebuilt_code = [&rc](u64 s, u64 e) { return rc.code(s, e); };
  c.infer = [this](u64 o, u64 r) { return infer(o, r); };
  c.alternates = [this](u64 t) { return alternates(t); };
  c.literal_at = [this](u64 t) { return literal_at(t); };
  c.local_base = [this](u64 t) { return reb.local_base(t); };
  c.span = [this](u64 t) { return reb.span(t); };
  c.static_home = [this](u64 b) { return static_home(b); };
  c.orig_refs = [this](u64 f) { return orig_refs(f); };
  c.orig_object_end = [this](u64 t) { return orig.object_end(t); };
  c.orig_padding = [this](u64 t) { return orig.in_padding(t); };
  c.containing = [this](u64 t) { return reb.containing(t); };
  c.end_of_previous = [this](u64 t) { return end_of_previous(t); };
  c.annotated_between = [this](u64 lo, u64 hi) { return annotated_between(lo, hi); };
  for (auto& [n, ea] : by_name) named_.insert(ea);
  for (auto& [r, o] : reb_to_orig) named_.insert(o);
  for (auto& [v, s] : orig.vtables) named_.insert(v);
  c.orig_named = [this](u64 t) { return named_.count(t) || orig.named_data(t); };
  c.folded_locals = [this](u64 base) {
    auto it = reb.by_va.find(base);
    return it == reb.by_va.end() ? 0 : int(it->second.size());
  };
  c.symbol_start = [this](u64 t) { return reb.by_va.count(t) != 0; };
  prebind_locals(votes_fn);
  return c;
}

void Pairing::release_code(u64 ostart, u64 oend, u64 rstart, u64 rend) {
  if (orig_cache_) orig_cache_->release(ostart, oend);
  if (rebuilt_cache_) rebuilt_cache_->release(rstart, rend);
}

void Pairing::prebind_locals(const std::function<std::map<u64, Votes>(Pairing&)>& votes_fn) {
  std::map<u64, Votes> votes;
  if (votes_fn) {
    votes = votes_fn(*this);
  } else {
    for (auto& [rva, ova] : voting_pairs()) {
      auto v = votes_of(rva, ova);
      if (!v.empty()) votes[rva] = std::move(v);
    }
  }
  for (auto& [base, o_base] : decide_locals(votes)) {
    cmp->bound.set(base, o_base);
    cmp->bound_o.set(o_base, base);
  }
}

std::vector<std::pair<u64, u64>> Pairing::voting_pairs() const {
  std::map<u64, u64> pairs;
  for (auto& [rva, ova] : reb_to_orig)
    if (reb.img.executable(rva) && orig.functions.count(ova)) pairs.emplace(rva, ova);
  // owners of local statics that resolve by their own names (an annotation's pairing comes first)
  for (auto& [base, owners] : reb.static_owner) {
    if (!owners) continue;
    for (u64 owner : *owners) {
      Key k = resolve_symbol(owner);
      if (k.kind == Key::VA && orig.functions.count(k.va)) pairs.emplace(owner, k.va);
    }
  }
  return std::vector<std::pair<u64, u64>>(pairs.begin(), pairs.end());
}

Pairing::Votes Pairing::votes_of(u64 rva, u64 ova) {
  const Image& O = orig.img;
  auto oc = cmp->orig_code(ova, orig.extent(ova));
  auto rc = cmp->rebuilt_code(rva, reb.extent(rva));
  Votes out;
  if (oc->insns.size() != rc->insns.size()) return out;
  for (size_t k = 0; k < oc->insns.size(); ++k) {
    const Lean &a = oc->insns[k], &b = rc->insns[k];
    auto fa = oc->fields(a), fb = rc->fields(b);
    if (a.mnem != b.mnem || !same_layout(a, fa, b, fb)) continue;
    for (size_t z = 0; z < fa.size(); ++z) {
      const Field &x = fa[z], &y = fb[z];
      if (!is_address(x.kind)) continue;
      auto at = reb.local_base(u64(y.value));
      u64 xv = u64(x.value);
      if (!at || O.executable(xv) || !O.flags(xv)) continue;
      u64 o_base = xv - at->second;
      bool fits = !orig.in_padding(o_base) && cmp->static_fits(o_base, at->first) && !annotated_between(o_base, xv);
      auto [it, fresh] = out[at->first].try_emplace(fits ? std::optional<u64>(o_base) : std::nullopt, at->second);
      if (!fresh) it->second = std::max(it->second, at->second);
    }
  }
  return out;
}

std::map<u64, u64> Pairing::decide_locals(const std::map<u64, Votes>& votes) const {
  std::map<u64, std::map<std::optional<u64>, std::set<u64>>> support;
  std::map<u64, std::set<std::optional<u64>>> owner_says;
  std::map<std::pair<u64, std::optional<u64>>, u64> reach;
  for (auto& [rva, v] : votes) {
    for (auto& [base, starts] : v) {
      for (auto& [o_base, off] : starts) {
        support[base][o_base].insert(rva);
        auto& r = reach[{base, o_base}];
        r = std::max(r, off);
      }
      auto owners = reb.owners_of(base);
      if (owners && *owners && (*owners)->count(rva))
        for (auto& [o_base, off] : starts) owner_says[base].insert(o_base);
    }
  }
  std::map<u64, std::optional<u64>> chosen;
  for (auto& [base, by_start] : support) {
    auto owners = reb.owners_of(base);
    if (owners && *owners && (*owners)->size() > 1) continue;   // ICF folded from several owners: first use
    auto os = owner_says.find(base);
    if (os != owner_says.end()) {
      if (os->second.size() == 1) chosen[base] = *os->second.begin();
      continue;
    }
    std::vector<std::pair<std::optional<u64>, size_t>> ranked;
    for (auto& [s, fs] : by_start) ranked.emplace_back(s, fs.size());
    std::sort(ranked.begin(), ranked.end(), [](auto& a, auto& b) {
      if (a.second != b.second) return a.second > b.second;
      if (a.first.has_value() != b.first.has_value()) return a.first.has_value();   // "cannot be a start" last
      return a.first.value_or(0) < b.first.value_or(0);
    });
    if (ranked.size() == 1 || ranked[0].second > ranked[1].second) chosen[base] = ranked[0].first;
  }
  std::map<u64, int> claims;
  for (auto& [b, o] : chosen) if (o) ++claims[*o];
  std::map<u64, u64> kept;
  for (auto& [b, o] : chosen) if (o && claims[*o] == 1) kept[b] = *o;
  std::vector<u64> starts;
  for (auto& [b, o] : kept) starts.push_back(o);
  std::sort(starts.begin(), starts.end());
  auto crosses = [&](u64 base, u64 o) {
    auto it = std::upper_bound(starts.begin(), starts.end(), o);
    auto r = reach.find({base, std::optional<u64>(o)});
    return it != starts.end() && *it <= o + (r == reach.end() ? 0 : r->second);
  };
  std::map<u64, u64> out;
  for (auto& [b, o] : kept) if (owner_says.count(b) || !crosses(b, o)) out[b] = o;
  return out;
}

std::optional<std::vector<u64>> Pairing::static_home(u64 base) const {
  auto owners = reb.owners_of(base);
  if (!owners || !*owners || (*owners)->empty()) return std::nullopt;   // an owner without a symbol: unknown
  std::vector<u64> homes;
  for (u64 owner : **owners) {
    Key r = resolve_symbol(owner);
    if (!(r.kind == Key::VA && orig.functions.count(r.va))) return std::nullopt;
    homes.push_back(r.va);
  }
  return homes;
}

std::vector<u64> Pairing::orig_refs(u64 f) {
  if (auto it = refs_of_.find(f); it != refs_of_.end()) return it->second;
  auto c = cmp->orig_code(f, orig.extent(f));
  std::set<u64> s;
  for (auto& x : c->field_list)
    if (is_address(x.kind)) s.insert(u64(x.value));
  return refs_of_.emplace(f, std::vector<u64>(s.begin(), s.end())).first->second;
}

Key Pairing::resolve_symbol(u64 t) const {
  if (auto it = reb_to_orig.find(t); it != reb_to_orig.end()) return Key::of_va(it->second);
  static const std::vector<std::string_view> none;
  auto bv = reb.by_va.find(t);
  const auto& names = bv == reb.by_va.end() ? none : bv->second;
  for (auto& n : names) if (is_const_name(n)) return Key::named_view(Key::CONST, n);
  for (auto& n : names) if (starts_with(n, "??_C@")) return Key::named_view(Key::STR, n);
  for (auto& n : names) if (auto it = by_name.find(n); it != by_name.end()) return Key::of_va(it->second);
  for (auto& n : names) if (auto it = by_name.find(reb.qualified(n)); it != by_name.end()) return Key::of_va(it->second);
  for (auto& n : names) if (starts_with(n, "??_R0")) return Key::named_view(Key::TD, n);
  for (auto& n : names) if (starts_with(n, "_TI")) return Key::named_view(Key::TI, n);
  for (auto& n : names) if (starts_with(n, "??_8")) return Key::named_view(Key::VBT, n);
  return names.empty() ? Key::named(Key::UNRESOLVED, hex(t)) : Key::named_view(Key::UNRESOLVED, names[0]);
}

Key Pairing::resolve(u64 t) const {
  Key r = resolve_symbol(t);
  if (r.kind == Key::UNRESOLVED) {
    auto at = reb.local_base(t);
    if (at) {
      if (auto b = cmp->bound.find(at->first)) return Key::of_va(*b + at->second);
    }
  }
  if (r.kind != Key::UNRESOLVED || reb.by_va.count(t)) return r;
  auto base = reb.containing(t);
  if (base) {
    Key b = resolve_symbol(*base);
    if (b.kind == Key::VA) {
      if (annotated_between(b.va, b.va + t - *base))
        return Key::named(Key::UNRESOLVED, std::string(reb.by_va.at(*base)[0]) + "+" + hex(t - *base));
      return Key::of_va(b.va + t - *base);
    }
  }
  return r;
}

bool Pairing::annotated_between(u64 lo, u64 hi) const {
  auto it = std::upper_bound(annotated_o.begin(), annotated_o.end(), lo);
  return it != annotated_o.end() && *it <= hi;
}

std::optional<u64> Pairing::end_of_previous(u64 t) const {
  if (!reb.by_va.count(t)) return std::nullopt;
  auto prev = reb.containing(t - 1);
  if (!prev) return std::nullopt;
  Key b = resolve_symbol(*prev);
  if (b.kind != Key::VA) return std::nullopt;
  return b.va + t - *prev;
}

std::vector<u64> Pairing::alternates(u64 t) const {
  auto bv = reb.by_va.find(t);
  if (bv == reb.by_va.end() || bv->second.size() < 2) return {};
  std::set<u64> named;
  for (auto& n : bv->second) if (auto it = by_name.find(n); it != by_name.end()) named.insert(it->second);
  for (auto& n : bv->second) if (auto it = by_name.find(reb.qualified(n)); it != by_name.end()) named.insert(it->second);
  if (auto it = reb_to_origs.find(t); it != reb_to_origs.end()) named.insert(it->second.begin(), it->second.end());
  return std::vector<u64>(named.begin(), named.end());
}

std::optional<std::pair<u64, Key>> Pairing::literal_at(u64 t) const {
  auto base = reb.containing(t);
  if (!base) return std::nullopt;
  Key k = resolve_symbol(*base);
  if ((k.kind == Key::CONST || k.kind == Key::STR) && i64(t - *base) < literal_size(reb.img, *base, k))
    return std::make_pair(*base, k);
  return std::nullopt;
}

bool Pairing::infer(u64 o_t, u64 r_t) {
  if (inferred_.contains({o_t, r_t})) return true;
  if (inferred_r_.contains(r_t) || reb_to_orig.count(r_t)) return false;
  if (!orig.functions.count(o_t) || !reb.by_va.count(r_t) || infer_depth_ >= 4) return false;
  u64 oend = orig.extent(o_t), rend = reb.extent(r_t);
  return cmp->journal.speculate([&] {
    inferred_.set({o_t, r_t}, true);
    inferred_r_.set(r_t, o_t);
    struct Depth { int& d; Depth(int& x) : d(++x) {} ~Depth() { --d; } } depth(infer_depth_);
    return cmp->function(o_t, oend, r_t, rend, 1).empty();
  });
}

}  // namespace verifier
