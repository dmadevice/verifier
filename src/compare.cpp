#include "compare.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>

namespace verifier {

constexpr int MAX_FUNCLET_DEPTH = 4;
constexpr int MAX_CHAIN = 32;

std::string Key::text() const { return kind == VA ? hex(va) : std::string(name); }

std::string_view keep_text(std::string_view s) {
  static std::unordered_set<std::string, SvHash, std::equal_to<>> kept;
  auto it = kept.find(s);
  if (it == kept.end()) it = kept.emplace(s).first;
  return *it;
}

bool Journal::speculate(const std::function<bool()>& attempt) {
  size_t mark = log.size();
  auto undo = [&] {
    for (size_t i = log.size(); i > mark; --i) log[i - 1]();
    log.resize(mark);
  };
  ++active;
  bool ok = false;
  try {
    ok = attempt();
  } catch (...) {
    --active;
    undo();
    throw;
  }
  --active;
  if (!ok) undo();
  else if (!active) log.resize(mark);   // held by no assumption any more
  return ok;
}

i64 const_size(std::string_view name) {
  if (starts_with(name, "__real@")) return i64(name.size()) / 2 - 3;
  if (starts_with(name, "__xmm@") || starts_with(name, "__mask@")) return 16;
  return 0;
}

i64 literal_size(const Image& img, u64 start, const Key& key) {
  if (key.kind == Key::STR) return i64(img.cstring(start, starts_with(key.name, "??_C@_1")).size());
  i64 n = const_size(key.name);
  return n ? n : 1;
}

// -- same_names: build hashes (`?A0x...@`, `<lambda_...>`) in a rebuilt name stand for one original hash ----------

namespace {

// a name split at its build hashes (`?A0x<hex>@`, `<lambda_<hex>>`): the pieces between them, and the hashes
void split_hashes(const Bytes& s, std::vector<Bytes>& pieces, std::vector<Bytes>& hashes) {
  auto hexc = [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); };
  size_t i = 0, last = 0;
  while (i < s.size()) {
    size_t e = std::string::npos;
    if (s.compare(i, 4, "?A0x") == 0) {
      size_t j = i + 4;
      while (j < s.size() && hexc(s[j])) ++j;
      if (j > i + 4 && j < s.size() && s[j] == '@') e = j + 1;
    } else if (s.compare(i, 8, "<lambda_") == 0) {
      size_t j = i + 8;
      while (j < s.size() && hexc(s[j])) ++j;
      if (j > i + 8 && j < s.size() && s[j] == '>') e = j + 1;
    }
    if (e != std::string::npos) {
      pieces.push_back(s.substr(last, i - last));
      hashes.push_back(s.substr(i, e - i));
      i = last = e;
    } else {
      ++i;
    }
  }
  pieces.push_back(s.substr(last));
}

const std::map<u64, std::vector<u64>>& no_vtables() {
  static const std::map<u64, std::vector<u64>> none;
  return none;
}
const NameMap& no_names() {
  static const NameMap none;
  return none;
}

// zero buf[lo, hi) (the part inside the buffer)
void mask(Bytes& buf, i64 lo, i64 hi) {
  lo = std::clamp<i64>(lo, 0, i64(buf.size()));
  hi = std::clamp<i64>(hi, lo, i64(buf.size()));
  std::fill(buf.begin() + lo, buf.begin() + hi, '\0');
}

}  // namespace

Comparer::Comparer(const Image* o, const Image* r, std::function<Key(u64)> res, const std::map<u64, std::vector<u64>>* vt,
                   const NameMap* nm)
    : O(o), R(r), resolve(std::move(res)), vtables(vt ? *vt : no_vtables()), names(nm ? *nm : no_names()) {
  orig_code = [this](u64 s, u64 e) { return std::make_shared<const Code>(*O, s, e); };
  rebuilt_code = [this](u64 s, u64 e) { return std::make_shared<const Code>(*R, s, e); };
}

bool Comparer::same_names(const NamePairs& names) {
  std::vector<std::pair<Bytes, Bytes>> pairs;   // (original hash, rebuilt hash)
  for (auto& [x, y] : names) {
    std::vector<Bytes> px, hx, py, hy;
    split_hashes(x, px, hx);
    split_hashes(y, py, hy);
    if (px != py || hx.size() != hy.size()) return false;
    for (size_t k = 0; k < hx.size(); ++k) pairs.emplace_back(hx[k], hy[k]);
  }
  std::unordered_map<std::string, std::string> new_o, new_r;
  for (auto& [o, r] : pairs) {
    if (o == r && !hash_o.contains(o) && !hash_r.contains(r)) continue;   // spelled the same: nothing to pair
    auto get = [](const JMap<std::string, std::string>& m, const std::unordered_map<std::string, std::string>& nw,
                  const std::string& k, const std::string& dflt) {
      if (auto p = m.find(k)) return *p;
      auto it = nw.find(k);
      return it == nw.end() ? dflt : it->second;
    };
    if (get(hash_r, new_r, r, o) != o || get(hash_o, new_o, o, r) != r) return false;
    new_r[r] = o;
    new_o[o] = r;
  }
  for (auto& [o, r] : pairs) {
    if (new_r.count(r)) hash_r.set(r, new_r[r]);
    if (new_o.count(o)) hash_o.set(o, new_o[o]);
  }
  return true;
}

bool Comparer::same_rtti(const Rtti& a, const Rtti& b) {
  if (a.present != b.present) return false;
  if (!a.present) return true;
  if (a.bad_sig || b.bad_sig) return a.bad_sig == b.bad_sig && a.sig == b.sig;
  if (a.off != b.off || a.cdoff != b.cdoff || a.attrs != b.attrs || a.bases.size() != b.bases.size()) return false;
  NamePairs names{{a.name, b.name}};
  for (size_t i = 0; i < a.bases.size(); ++i) {
    const BaseDesc &x = a.bases[i], &y = b.bases[i];
    if (x.ncont != y.ncont || x.mdisp != y.mdisp || x.pdisp != y.pdisp || x.vdisp != y.vdisp || x.attr != y.attr) return false;
    names.emplace_back(x.name, y.name);
  }
  return same_names(names);
}

bool Comparer::same_catchables(const ThrowInfoSig& a, const ThrowInfoSig& b) {
  if (a.attrs != b.attrs || a.types.size() != b.types.size()) return false;
  NamePairs names;
  for (size_t i = 0; i < a.types.size(); ++i) {
    const CatchableSig &x = a.types[i], &y = b.types[i];
    if (x.props != y.props || x.mdisp != y.mdisp || x.pdisp != y.pdisp || x.vdisp != y.vdisp || x.size != y.size) return false;
    names.emplace_back(x.name, y.name);
  }
  return same_names(names);
}

std::optional<Key> Comparer::bind_local(u64 o_t, u64 r_t) {
  auto at = local_base(r_t);
  if (!at || O->executable(o_t)) return std::nullopt;
  auto [base, off] = *at;
  u64 o_base = o_t - off;
  if (!bound.contains(base) && !bound_o.contains(o_base)) {
    if (orig_padding(o_base) || !static_fits(o_base, base) || static_overlaps(o_base, o_t, base)) return std::nullopt;
    auto homes = static_home(base);
    if (homes) {
      bool any = false;
      for (u64 f : *homes) if (refers_to(f, o_base, std::max<u64>(span(base), 1))) { any = true; break; }
      if (!any) return std::nullopt;
    }
    bound.set(base, o_base);
    bound_o.set(o_base, base);
  } else if (bound.contains(base) && !bound_o.contains(o_base) && !O->writable(o_base) && !R->writable(base)) {
    int same = 0;
    for (auto& [ob, rb] : bound_o.items()) same += rb == base;
    if (same < folded_locals(base)) {
      Bytes rb = Bytes(R->bytes(base, i64(span(base))));
      i64 n = i64(rstrip_char(rb, '\0').size());
      if (!n) n = 1;
      if (O->bytes(o_base, n) == O->bytes(*bound.find(base), n) && O->bytes(*bound.find(base), n) == R->bytes(base, n))
        bound_o.set(o_base, base);
    }
  }
  auto p = bound_o.find(o_base);
  if (p && *p == base) return Key::of_va(o_t);
  return std::nullopt;
}

bool Comparer::static_fits(u64 o_base, u64 base) {
  if (!O->flags(o_base)) return true;
  i64 n = i64(rstrip_char(R->bytes(base, i64(span(base))), '\0').size());
  Bytes a(O->bytes(o_base, n)), b(R->bytes(base, n));
  size_t lo = R->reloc_lower_bound(base), hi = R->reloc_lower_bound(base + u64(n));
  for (size_t k = lo; k < hi; ++k) {
    u64 off = R->reloc_sorted[k] - base;
    if (!O->has_reloc(o_base + off)) return false;
    i64 m = std::min<i64>(8, n - i64(off));
    mask(a, i64(off), i64(off) + m);
    mask(b, i64(off), i64(off) + m);
  }
  return a == b;
}

bool Comparer::static_overlaps(u64 o_base, u64 o_t, u64 base) {
  if (annotated_between(o_base, o_t)) return true;
  for (auto& [ob, rb] : bound_o.items()) if (rb != base && o_base < ob && ob <= o_t) return true;
  return false;
}

bool Comparer::refers_to(u64 f, u64 lo, u64 n) {
  auto refs = orig_refs(f);
  auto it = std::lower_bound(refs.begin(), refs.end(), lo);
  return it != refs.end() && *it < lo + n;
}

bool Comparer::is_alternate(u64 o_t, u64 r_t) {
  auto alts = alternates(r_t);
  return std::find(alts.begin(), alts.end(), o_t) != alts.end();
}

bool Comparer::infer_vtable(u64 o_vt, u64 r_vt) {
  if (auto p = vt_r.find(r_vt); p && *p == o_vt) return true;
  if (vt_r.contains(r_vt) || vt_o.contains(o_vt) || !vtables.count(o_vt) || !symbol_start(r_vt)) return false;
  return journal.speculate([&] {
    vt_r.set(r_vt, o_vt);
    vt_o.set(o_vt, r_vt);
    return !vtable(o_vt, r_vt).has_value();
  });
}

std::optional<Problem> Comparer::ref(u64 o_t, u64 r_t, int access) {
  if (o_t == O->base && r_t == R->base) return std::nullopt;   // __ImageBase
  auto oi = O->imports.find(o_t);
  auto ri = R->imports.find(r_t);
  if (oi != O->imports.end() || ri != R->imports.end()) {
    const Import* a = oi == O->imports.end() ? nullptr : &oi->second;
    const Import* b = ri == R->imports.end() ? nullptr : &ri->second;
    if ((a == nullptr) == (b == nullptr) && (!a || *a == *b)) return std::nullopt;
    return Problem{"reference", "import " + imp_str(a) + " vs " + imp_str(b)};
  }
  Key key = resolve(r_t);
  if (!key.is_va(o_t) && is_alternate(o_t, r_t)) key = Key::of_va(o_t);
  if (key.kind == Key::UNRESOLVED || (!key.is_va(o_t) && local_base(r_t).has_value())) {
    if (auto b = bind_local(o_t, r_t)) key = *b;
  }
  if (key.kind == Key::UNRESOLVED && O->executable(o_t) && infer(o_t, r_t)) key = Key::of_va(o_t);
  if (key.kind == Key::UNRESOLVED && vtables.count(o_t) && infer_vtable(o_t, r_t)) key = Key::of_va(o_t);
  u64 o_at = o_t, r_at = r_t;
  std::optional<std::pair<u64, Key>> lit;
  if (key.kind == Key::UNRESOLVED) lit = literal_at(r_t);
  if (lit) {
    r_at = lit->first;
    key = lit->second;
    o_at = o_t - (r_t - r_at);
  }
  if (key.kind == Key::UNRESOLVED && !O->executable(o_t) && !O->writable(o_t)) {
    auto base = containing(r_t);
    if (base && infer_data(o_t - (r_t - *base), *base)) key = Key::of_va(o_t);
  }
  if (key.kind == Key::CONST) {
    i64 n = const_size(key.name);
    if (!n) n = access ? access : 4;
    if (O->bytes(o_at, n) != R->bytes(r_at, n) || (lit && !same_read(o_t, r_t, access, r_at + u64(n))))
      return Problem{"data", "constant " + std::string(key.name) + " differs from " + hex(o_t)};
    return std::nullopt;
  }
  if (key.kind == Key::STR) {
    bool wide = starts_with(key.name, "??_C@_1");
    Bytes rs = R->cstring(r_at, wide);
    if (O->cstring(o_at, wide) != rs || (lit && !same_read(o_t, r_t, access, r_at + rs.size(), wide)))
      return Problem{"data", "string " + std::string(key.name.substr(0, 40)) + " differs from " + hex(o_t)};
    return std::nullopt;
  }
  if (key.kind == Key::TD) {
    bool same = same_names({{type_name(*O, o_at), type_name(*R, r_at)}});
    if (same) return std::nullopt;
    return Problem{"reference", hex(o_t) + " vs " + std::string(key.name)};
  }
  if (key.kind == Key::TI && o_at == o_t && r_at == r_t) return throw_info_cmp(o_t, r_t, key.name);
  if (key.kind == Key::VBT && o_at == o_t && r_at == r_t) {
    u64 n = span(r_t);
    size_t i = R->reloc_lower_bound(r_t);
    if (i < R->reloc_sorted.size() && R->reloc_sorted[i] < r_t + n) n = R->reloc_sorted[i] - r_t;
    if (O->bytes(o_t, i64(n)) == R->bytes(r_t, i64(n))) return std::nullopt;
    return Problem{"data", "vbtable " + std::string(key.name.substr(0, 40)) + " differs from " + hex(o_t)};
  }
  if (!key.is_va(o_t)) {
    if (!access && !O->executable(o_t) && !orig_named(o_t)) {
      auto e = end_of_previous(r_t);
      if (e && *e == o_t) return std::nullopt;   // one past the end of the data object before (a loop bound)
    }
    return Problem{"reference", hex(o_t) + " vs " + (key.kind == Key::UNRESOLVED ? std::string(key.name) : hex(key.va))};
  }
  if (vtables.count(o_t)) return vtable(o_t, r_t);
  if (O->executable(o_t)) return std::nullopt;   // code: identity; callees are verified on their own
  if (access) return accessed(o_t, r_t, access);
  return rodata(o_t, r_t);   // address taken: the object's initial contents, writable or not
}

bool Comparer::same_read(u64 o_t, u64 r_t, int access, u64 r_end, std::optional<bool> wide) {
  if (!access && wide) return O->cstring(o_t, *wide) == R->cstring(r_t, *wide);
  i64 n = access ? access : i64(r_end) - i64(r_t);
  return n <= 0 || O->bytes(o_t, n) == R->bytes(r_t, n);
}

std::optional<Problem> Comparer::accessed(u64 o_t, u64 r_t, int n) {
  Bytes a(O->bytes(o_t, n)), b(R->bytes(r_t, n));
  std::vector<i64> ptrs;
  for (i64 p = i64(r_t) - 7; p < i64(r_t) + n; ++p) {
    if (R->has_reloc(u64(p))) {
      if (!O->has_reloc(u64(i64(o_t) + (p - i64(r_t))))) return Problem{"data", std::to_string(n) + " bytes at " + hex(o_t) + " differ: a pointer only in the rebuild"};
      ptrs.push_back(p - i64(r_t));
    }
  }
  for (i64 off : ptrs) {
    i64 lo = std::max<i64>(off, 0), hi = std::min<i64>(off + 8, n);
    mask(a, lo, hi);
    mask(b, lo, hi);
  }
  if (a != b) return Problem{"data", std::to_string(n) + " bytes at " + hex(o_t) + " differ"};
  for (i64 off : ptrs) {
    u64 o_p = O->u64_at(u64(i64(o_t) + off)), r_p = R->u64_at(u64(i64(r_t) + off));
    if (infer_data(o_p, r_p)) continue;
    auto p = ref(o_p, r_p, 0);
    if (p) {
      std::string offs = off < 0 ? hex_signed(off) : "+" + hex(u64(off));
      return Problem{p->first, "pointer at " + hex(o_t) + offs + ": " + p->second};
    }
  }
  return std::nullopt;
}

std::optional<Problem> Comparer::rodata(u64 o_t, u64 r_t) {
  auto k = std::make_pair(o_t, r_t);
  if (auto m = memo_ro.find(k)) return *m;
  memo_ro.set(k, std::nullopt);   // tables that point at each other count as consistent
  u64 n = span(r_t);
  Bytes all(R->bytes(r_t, i64(n)));
  i64 want = i64(rstrip_char(all, '\0').size());
  size_t lo = R->reloc_lower_bound(r_t), hi = R->reloc_lower_bound(r_t + n);
  std::vector<i64> ptrs;
  for (size_t i = lo; i < hi; ++i) ptrs.push_back(i64(R->reloc_sorted[i] - r_t));
  i64 size = std::max<i64>(want, std::min<i64>(i64(n), i64(orig_object_end(o_t)) - i64(o_t)));
  for (i64 off : ptrs) if (off < want) size = std::max(size, off + 8);
  std::vector<i64> kept;
  for (i64 off : ptrs) if (off < size) kept.push_back(off);
  Bytes a(O->bytes(o_t, size)), b(R->bytes(r_t, size));
  for (i64 off : kept) {
    mask(a, off, off + 8);
    mask(b, off, off + 8);
  }
  std::optional<Problem> res;
  std::string what = (O->writable(o_t) || R->writable(r_t)) ? "initial data" : "read-only data";
  if (a != b) res = Problem{"data", what + " at " + hex(o_t) + " differs"};
  if (!res) {
    for (i64 off : kept) {
      if (!O->has_reloc(o_t + u64(off))) {
        res = Problem{"data", what + " at " + hex(o_t) + ": +" + hex(u64(off)) + " is a pointer only in the rebuild"};
        break;
      }
      u64 o_p = O->u64_at(o_t + u64(off)), r_p = R->u64_at(r_t + u64(off));
      if (infer_data(o_p, r_p)) continue;
      auto p = ref(o_p, r_p, 0);
      if (p) {
        res = Problem{p->first, "pointer at " + hex(o_t) + "+" + hex(u64(off)) + ": " + p->second};
        break;
      }
    }
  }
  memo_ro.set(k, res);
  return res;
}

bool Comparer::infer_data(u64 o_t, u64 r_t) {
  if (auto p = data_r.find(r_t); p && *p == o_t) return true;
  if (data_r.contains(r_t) || data_o.contains(o_t) || resolve(r_t).kind != Key::UNRESOLVED) return false;
  if (!symbol_start(r_t) || O->writable(o_t) || R->writable(r_t) || O->executable(o_t) || R->executable(r_t)) return false;
  if (!O->flags(o_t)) return false;
  auto rb = R->bytes(r_t, i64(span(r_t)));
  if (rb.find_first_not_of('\0') == std::string_view::npos) return false;   // zero-filled (strip(b"\0") is empty)
  return journal.speculate([&] {
    data_r.set(r_t, o_t);
    data_o.set(o_t, r_t);
    return !rodata(o_t, r_t).has_value();
  });
}

std::optional<Problem> Comparer::throw_info_cmp(u64 o_t, u64 r_t, std::string_view name) {
  ThrowInfoSig os = throw_info(*O, o_t), rs = throw_info(*R, r_t);
  if (!same_catchables(os, rs)) return Problem{"reference", hex(o_t) + " vs " + std::string(name) + ": catchable types differ"};
  for (size_t i = 0; i < std::min(os.funcs.size(), rs.funcs.size()); ++i) {
    u64 a = os.funcs[i], b = rs.funcs[i];
    if (bool(a) != bool(b)) return Problem{"reference", hex(o_t) + " vs " + std::string(name) + ": function " + hex(a) + " vs " + hex(b)};
    if (a) {
      auto p = ref(a, b, 0);
      if (p) return Problem{p->first, std::string(name) + ": " + p->second};
    }
  }
  return std::nullopt;
}

std::optional<Problem> Comparer::vtable(u64 o_vt, u64 r_vt) {
  auto k = std::make_pair(o_vt, r_vt);
  if (auto m = memo_vt.find(k)) return *m;
  memo_vt.set(k, std::nullopt);   // cycles (a slot that refers back) count as consistent
  std::optional<Problem> res;
  const auto& slots = vtables.at(o_vt);
  for (size_t i = 0; i < slots.size(); ++i) {
    u64 s = slots[i];
    u64 r_s = R->u64_at(r_vt + 8 * i);
    Key got = resolve(r_s);
    if (got.is_va(s) || is_alternate(s, r_s)) continue;
    if (got.kind == Key::UNRESOLVED && O->executable(s) && infer(s, r_s)) continue;
    res = Problem{"vtable", "slot " + std::to_string(i) + " of " + hex(o_vt) + ": " + hex(s) + " vs " +
                                got.text()};
    break;
  }
  if (!res && !same_rtti(rtti(*O, O->u64_at(o_vt - 8)), rtti(*R, R->u64_at(r_vt - 8))))
    res = Problem{"vtable", "RTTI of " + hex(o_vt) + " differs"};
  memo_vt.set(k, res);
  return res;
}

FnMemo Comparer::code(u64 ostart, u64 oend, u64 rstart, u64 rend) {
  FnMemo cr;
  cr.oc = orig_code(ostart, oend);
  cr.rc = rebuilt_code(rstart, rend);
  const Code &oc = *cr.oc, &rc = *cr.rc;
  Problems& probs = cr.probs;
  auto decoded = [](const Code& c) { i64 s = 0; for (auto& i : c.insns) s += i.size; return s; };
  if (!oc.complete || !rc.complete)
    probs.push_back({"undecodable", "decoded " + std::to_string(decoded(oc)) + "/" + std::to_string(oc.cut) + " | " +
                                        std::to_string(decoded(rc)) + "/" + std::to_string(rc.cut) + " code bytes"});
  if (oc.code.size() != rc.code.size() || oc.cut != rc.cut || oc.resume != rc.resume || oc.insns.size() != rc.insns.size()) {
    probs.push_back({"length", std::to_string(oc.code.size()) + "/" + std::to_string(rc.code.size()) + " bytes, code " +
                                   std::to_string(oc.cut) + "/" + std::to_string(rc.cut)});
    return cr;
  }
  for (size_t k = 0; k < oc.insns.size(); ++k) {
    const Lean &a = oc.insns[k], &b = rc.insns[k];
    auto fa = oc.fields(a), fb = rc.fields(b);
    auto enc = [&] {
      return "@" + std::to_string(k) + ": `" + oc.insn(a).text() + "` | `" + rc.insn(b).text() + "`";
    };
    if (!same_layout(a, fa, b, fb) || !same_outside_fields(oc.bytes(a), rc.bytes(b), fa)) { probs.push_back({"encoding", enc()}); continue; }
    for (size_t z = 0; z < fa.size(); ++z) {
      if (fa[z].kind == F_TBL) {
        if (fa[z].value != fb[z].value)
          probs.push_back({"encoding", "@" + std::to_string(k) + ": table offset " + hex_signed(fa[z].value) + " vs " + hex_signed(fb[z].value)});
        continue;
      }
      auto p = ref(u64(fa[z].value), u64(fb[z].value), fa[z].access);
      if (p) probs.push_back({p->first, "@" + std::to_string(k) + ": " + p->second});
    }
  }
  if (!(oc.table_region() == rc.table_region())) probs.push_back({"encoding", "switch table region differs"});
  if (!(oc.outside_tables() == rc.outside_tables())) probs.push_back({"encoding", "switch tables after the function differ"});
  return cr;
}

Problems Comparer::unwinds(u64 ostart, u64 oend, u64 rstart, u64 rend, int depth) {
  auto ob = O->pdata_in(ostart, oend), rb = R->pdata_in(rstart, rend);
  bool same = ob.size() == rb.size();
  for (size_t i = 0; same && i < ob.size(); ++i)
    if (ob[i] - ostart != rb[i] - rstart || O->pdata.at(ob[i]).first - ostart != R->pdata.at(rb[i]).first - rstart) same = false;
  if (!same) return {{"unwind", ".pdata ranges differ"}};
  Problems probs;
  for (size_t i = 0; i < ob.size(); ++i) {
    auto p = unwind_info(O->pdata.at(ob[i]).second, R->pdata.at(rb[i]).second, ostart, oend, rstart, rend, depth);
    probs.insert(probs.end(), p.begin(), p.end());
  }
  return probs;
}

Problems Comparer::unwind_info(u32 ou, u32 ru, u64 ostart, u64 oend, u64 rstart, u64 rend, int depth, int chain_depth) {
  Unwind o = O->unwind(ou), r = R->unwind(ru);
  if (o.body != r.body) return {{"unwind", "UNWIND_INFO codes differ"}};
  if (o.has_chain != r.has_chain || o.handler.has_value() != r.handler.has_value()) return {{"unwind", "chain/handler presence differs"}};
  if (o.has_chain) {
    if (O->base + o.chain_begin - ostart != R->base + r.chain_begin - rstart || O->base + o.chain_end - ostart != R->base + r.chain_end - rstart)
      return {{"unwind", "chained range differs"}};
    if (chain_depth >= MAX_CHAIN) return {{"unwind", "unwind chain too long"}};
    return unwind_info(o.chain_unwind, r.chain_unwind, ostart, oend, rstart, rend, depth, chain_depth + 1);
  }
  if (!o.handler) return {};
  Key got = resolve(*r.handler);
  if (!got.is_va(*o.handler)) return {{"unwind", "handler " + hex(*o.handler) + " vs " + got.text()}};
  auto it = names.find(*o.handler);
  return handler_data(it == names.end() ? "" : it->second, *o.hdata, *r.hdata, ostart, oend, rstart, rend, depth);
}

// -- EH ----------------------------------------------------------------------------------------------------------

namespace {
std::optional<u64> extent_or_leaf(const Image& img, u64 va) {   // .pdata's extent, else a leaf function's
  auto e = img.extent(va);
  return e ? e : leaf_extent(img, va);
}
}  // namespace

class EHContext {
 public:
  EHContext(Comparer* c, u64 os, u64 oe, u64 rs, u64 re, int d) : c(c), O(c->O), R(c->R), ostart(os), oend(oe), rstart(rs), rend(re), depth(d) {}
  Comparer* c;
  const Image *O, *R;
  u64 ostart, oend, rstart, rend;
  int depth;
  std::vector<u64> ofun, rfun;
  Problems probs;

  void funclet(u32 orva, u32 rrva) {
    if ((orva == 0) != (rrva == 0)) { probs.push_back({"eh", "funclet presence differs"}); return; }
    if (orva == 0) return;
    u64 o = O->base + orva, r = R->base + rrva;
    auto io = std::find(ofun.begin(), ofun.end(), o), ir = std::find(rfun.begin(), rfun.end(), r);
    long ix = io == ofun.end() ? -1 : long(io - ofun.begin()), jx = ir == rfun.end() ? -1 : long(ir - rfun.begin());
    if (ix != jx) { probs.push_back({"eh", "funclet sharing differs"}); return; }
    if (ix >= 0) return;
    ofun.push_back(o);
    rfun.push_back(r);
    if ((ostart <= o && o < oend) || (rstart <= r && r < rend)) {
      if (o - ostart != r - rstart) probs.push_back({"eh", "in-function handler offset differs"});
      return;
    }
    auto oe = extent_or_leaf(*O, o), re = extent_or_leaf(*R, r);
    if (O->pdata.count(o) != R->pdata.count(r)) { probs.push_back({"eh", "funclet " + hex(o) + ": .pdata presence differs"}); return; }
    if (!oe || !re) { probs.push_back({"eh", "funclet " + hex(o) + " has no .pdata"}); return; }
    if (depth >= MAX_FUNCLET_DEPTH) { probs.push_back({"eh", "funclet nesting too deep"}); return; }
    for (auto& [cat, why] : c->function(o, *oe, r, *re, depth + 1))
      probs.push_back({"eh", "funclet " + std::to_string(ofun.size() - 1) + ": " + cat + ": " + why});
  }

  // ('p', off) / ('f', k, off) / ('?',)
  struct Where {
    char t; i64 k, off;
    bool operator==(const Where& o) const { return t == o.t && k == o.k && off == o.off; }
  };
  Where where(const Image& img, u64 va, u64 start, u64 end, const std::vector<u64>& funs) {
    if (start <= va && va < end) return {'p', 0, i64(va - start)};
    for (size_t k = 0; k < funs.size(); ++k) {
      u64 f = funs[k];
      auto fe = extent_or_leaf(img, f);
      if (fe && *fe && f <= va && va < *fe) return {'f', i64(k), i64(va - f)};
    }
    return {'?', 0, 0};
  }

  void handlers(u64 oarr, u64 rarr, i64 n) {
    for (i64 i = 0; i < n; ++i) {
      u64 o = oarr + 20 * u64(i), r = rarr + 20 * u64(i);
      u32 oadj = O->u32_at(o), otd = O->u32_at(o + 4), oaddr = O->u32_at(o + 12);
      i32 odisp = O->i32_at(o + 8), oframe = O->i32_at(o + 16);
      u32 radj = R->u32_at(r), rtd = R->u32_at(r + 4), raddr = R->u32_at(r + 12);
      i32 rdisp = R->i32_at(r + 8), rframe = R->i32_at(r + 16);
      if (oadj != radj || odisp != rdisp || oframe != rframe) { probs.push_back({"eh", "catch handler " + std::to_string(i) + " differs"}); continue; }
      if ((otd == 0) != (rtd == 0) ||
          (otd && !c->same_names({{type_name(*O, O->base + otd), type_name(*R, R->base + rtd)}}))) {
        probs.push_back({"eh", "catch type " + std::to_string(i) + " differs"});
        continue;
      }
      funclet(oaddr, raddr);
    }
  }

  Problems funcinfo(u64 ofi, u64 rfi) {
    if (c->memo_fi.contains(ofi) || c->memo_fir.contains(rfi)) {
      auto a = c->memo_fi.find(ofi);
      auto b = c->memo_fir.find(rfi);
      bool ok = a && *a == rfi && b && *b == ofi;
      return ok ? Problems{} : Problems{{"eh", "FuncInfo sharing differs"}};
    }
    c->memo_fi.set(ofi, rfi);
    c->memo_fir.set(rfi, ofi);
    auto rd = [](const Image* im, u64 p, u32 (&m)[10]) { for (int k = 0; k < 10; ++k) m[k] = im->u32_at(p + 4 * k); };
    u32 om[10], rm[10];
    rd(O, ofi, om);
    rd(R, rfi, rm);
    // magic, max_state(i), unwind_map, ntry, try_map, nip, ip_map, disp_help(i), es_list, ehflags(i)
    if (om[0] != rm[0] || om[1] != rm[1] || om[3] != rm[3] || om[5] != rm[5] || om[7] != rm[7] || om[9] != rm[9])
      return {{"eh", "FuncInfo header differs"}};
    i32 max_state = i32(om[1]);
    u32 ntry = om[3], nip = om[5];
    if (max_state > 0x10000 || ntry > 0x10000 || nip > 0x100000) return {{"eh", "FuncInfo out of range"}};
    for (i32 i = 0; i < max_state; ++i) {
      i32 ost = O->i32_at(O->base + om[2] + 8 * u64(i)), rst = R->i32_at(R->base + rm[2] + 8 * u64(i));
      u32 oact = O->u32_at(O->base + om[2] + 8 * u64(i) + 4), ract = R->u32_at(R->base + rm[2] + 8 * u64(i) + 4);
      if (ost != rst) { probs.push_back({"eh", "unwind map entry " + std::to_string(i) + " differs"}); continue; }
      funclet(oact, ract);
    }
    for (u32 i = 0; i < ntry; ++i) {
      u64 ob = O->base + om[4] + 20 * u64(i), rb = R->base + rm[4] + 20 * u64(i);
      i32 o4[4], r4[4];
      for (int z = 0; z < 4; ++z) { o4[z] = O->i32_at(ob + 4 * z); r4[z] = R->i32_at(rb + 4 * z); }
      if (std::memcmp(o4, r4, sizeof o4) != 0) { probs.push_back({"eh", "try block " + std::to_string(i) + " differs"}); continue; }
      handlers(O->base + O->u32_at(ob + 16), R->base + R->u32_at(rb + 16), o4[3]);
    }
    if ((om[8] == 0) != (rm[8] == 0)) {
      probs.push_back({"eh", "exception specification presence differs"});
    } else if (om[8]) {
      i32 on = O->i32_at(O->base + om[8]), rn = R->i32_at(R->base + rm[8]);
      u32 oarr = O->u32_at(O->base + om[8] + 4), rarr = R->u32_at(R->base + rm[8] + 4);
      if (on != rn || !(0 <= on && on <= 0x100)) probs.push_back({"eh", "exception specification differs"});
      else handlers(O->base + oarr, R->base + rarr, on);
    }
    for (u32 i = 0; i < nip; ++i) {
      u32 oip = O->u32_at(O->base + om[6] + 8 * u64(i)), rip = R->u32_at(R->base + rm[6] + 8 * u64(i));
      i32 ost = O->i32_at(O->base + om[6] + 8 * u64(i) + 4), rst = R->i32_at(R->base + rm[6] + 8 * u64(i) + 4);
      Where ow = where(*O, O->base + oip, ostart, oend, ofun), rw = where(*R, R->base + rip, rstart, rend, rfun);
      if (ost != rst || !(ow == rw) || ow.t == '?') { probs.push_back({"eh", "IP-to-state entry " + std::to_string(i) + " differs"}); break; }
    }
    return probs;
  }

  Problems scope_table(u64 od, u64 rd) {
    u32 n = O->u32_at(od);
    if (n != R->u32_at(rd) || n > 0x1000) return {{"eh", "scope table size differs"}};
    for (u32 i = 0; i < n; ++i) {
      u64 oo = od + 4 + 16 * u64(i), ro = rd + 4 + 16 * u64(i);
      u32 ob = O->u32_at(oo), oe = O->u32_at(oo + 4), oh = O->u32_at(oo + 8), ot = O->u32_at(oo + 12);
      u32 rb = R->u32_at(ro), re = R->u32_at(ro + 4), rh = R->u32_at(ro + 8), rt = R->u32_at(ro + 12);
      Where ow1 = where(*O, O->base + ob, ostart, oend, {}), ow2 = where(*O, O->base + oe, ostart, oend + 1, {});
      Where rw1 = where(*R, R->base + rb, rstart, rend, {}), rw2 = where(*R, R->base + re, rstart, rend + 1, {});
      if (!(ow1 == rw1) || !(ow2 == rw2) || ow1.t == '?' || ow2.t == '?') { probs.push_back({"eh", "scope " + std::to_string(i) + " range differs"}); continue; }
      if ((ot == 0) != (rt == 0) || (ot && O->base + ot - ostart != R->base + rt - rstart)) { probs.push_back({"eh", "scope " + std::to_string(i) + " target differs"}); continue; }
      if (oh < 0x10 || rh < 0x10) {   // EXCEPTION_EXECUTE_HANDLER etc. are constants, not RVAs
        if (oh != rh) probs.push_back({"eh", "scope " + std::to_string(i) + " filter differs"});
        continue;
      }
      funclet(oh, rh);
    }
    return probs;
  }
};

Problems Comparer::handler_data(std::string_view handler, u64 od, u64 rd, u64 ostart, u64 oend, u64 rstart, u64 rend, int depth) {
  EHContext ctx(this, ostart, oend, rstart, rend, depth);
  if (handler == "__CxxFrameHandler3") return ctx.funcinfo(O->base + O->u32_at(od), R->base + R->u32_at(rd));
  if (handler == "__GSHandlerCheck") {
    if (gs_data(*O, od) != gs_data(*R, rd)) return {{"eh", "GS cookie data differs"}};
    return {};
  }
  if (handler == "__GSHandlerCheck_EH") {
    Problems p = ctx.funcinfo(O->base + O->u32_at(od), R->base + R->u32_at(rd));
    if (gs_data(*O, od + 4) != gs_data(*R, rd + 4)) p.push_back({"eh", "GS cookie data differs"});
    return p;
  }
  if (handler == "__C_specific_handler") return ctx.scope_table(od, rd);
  return {{"eh", "handler " + (handler.empty() ? std::string("unknown") : std::string(handler)) + " data is not verifiable"}};
}

Problems Comparer::function(u64 ostart, u64 oend, u64 rstart, u64 rend, int depth) {
  auto k = std::make_pair(ostart, rstart);
  if (auto m = memo_fn.find(k)) return m->probs;
  memo_fn.set(k, FnMemo{});
  FnMemo m = code(ostart, oend, rstart, rend);
  if (m.probs.empty()) m.probs = unwinds(ostart, oend, rstart, rend, depth);
  Problems probs = m.probs;
  memo_fn.set(k, std::move(m));
  return probs;
}

}  // namespace verifier
