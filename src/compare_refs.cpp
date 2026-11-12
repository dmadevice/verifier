// Comparison of what code refers to: local statics, referenced data, vtables and ThrowInfo, and the guesses that pair
// unannotated functions, data and vtables by their contents.
#include <algorithm>

#include "compare.hpp"

namespace verifier {

namespace {

// zero buf[lo, hi) (the part inside the buffer)
void mask(Bytes& buf, i64 lo, i64 hi) {
  lo = std::clamp<i64>(lo, 0, i64(buf.size()));
  hi = std::clamp<i64>(hi, lo, i64(buf.size()));
  std::fill(buf.begin() + lo, buf.begin() + hi, '\0');
}

}  // namespace

// A local static the votes did not place (or a further original of a folded read-only one): r_t's static stands for
// o_t's when it fits there, a guess the matching decides (its rules: Matching). Judging: whether the matching holds it.
bool Comparer::bind_local(u64 o_t, u64 r_t) {
  auto at = ctx->local_base(r_t);
  if (!at || O->executable(o_t)) return false;
  auto [base, off] = *at;
  u64 o_base = o_t - off;
  if (m.mode() == Matching::Mode::Judge) {
    auto p = m.local_of(base);
    return (p && *p == o_base) || m.holds(Kind::Local, o_base, base);
  }
  if (m.original_fixed(o_base)) return false;  // another static's, by the votes
  if (auto fixed = m.local_of(base)) {
    if (*fixed == o_base) return true;
    // a further original of a folded read-only static
    if (O->writable(o_base) || R->writable(base)) return false;
  } else {
    if (ctx->orig_padding(o_base) || !static_fits(o_base, base) || ctx->annotated_between(o_base, o_t)) return false;
    if (auto homes = ctx->static_home(base)) {
      bool any = false;
      for (u64 f : *homes)
        if (refers_to(f, o_base, std::max<u64>(ctx->span(base), 1))) {
          any = true;
          break;
        }
      if (!any) return false;
    }
  }
  return m.assume(Kind::Local, o_base, base, off);
}

// a folded read-only static's further original: its bytes are the first original's and the rebuilt static's
bool Comparer::folded_extra(u64 base, u64 o_primary, u64 o_base) {
  if (O->writable(o_base) || R->writable(base)) return false;
  i64 n = i64(rstrip_char(R->bytes(base, i64(ctx->span(base))), '\0').size());
  if (!n) n = 1;
  return O->bytes(o_base, n) == O->bytes(o_primary, n) && O->bytes(o_primary, n) == R->bytes(base, n);
}

bool static_fits(const Image& O, const Image& R, u64 o_base, u64 base, u64 span) {
  if (!O.flags(o_base)) return true;
  i64 n = i64(rstrip_char(R.bytes(base, i64(span)), '\0').size());
  Bytes a(O.bytes(o_base, n)), b(R.bytes(base, n));
  size_t lo = R.reloc_lower_bound(base), hi = R.reloc_lower_bound(base + u64(n));
  for (size_t k = lo; k < hi; ++k) {
    u64 off = R.reloc_sorted[k] - base;
    if (!O.has_reloc(o_base + off)) return false;
    i64 m = std::min<i64>(8, n - i64(off));
    mask(a, i64(off), i64(off) + m);
    mask(b, i64(off), i64(off) + m);
  }
  return a == b;
}

bool Comparer::static_fits(u64 o_base, u64 base) {
  return verifier::static_fits(*O, *R, o_base, base, ctx->span(base));
}

bool Comparer::refers_to(u64 f, u64 lo, u64 n) {
  auto refs = ctx->orig_refs(f);
  auto it = std::lower_bound(refs.begin(), refs.end(), lo);
  return it != refs.end() && *it < lo + n;
}

bool Comparer::is_alternate(u64 o_t, u64 r_t) {
  auto alts = ctx->alternates(r_t);
  return std::find(alts.begin(), alts.end(), o_t) != alts.end();
}

bool Comparer::is_vtable_slot(u64 o_vt, u64 off) const {
  auto it = vtables.find(o_vt);
  return it != vtables.end() && off && off % 8 == 0 && off < 8 * it->second.size();
}

// The guesses: an unresolved rebuilt function, vtable or read-only object standing for an original one. Exploring,
// each is assumed and compared (a function later: Matching queues it); judging, the matching answers.
bool Comparer::infer_function(u64 o_t, u64 r_t) {
  return ctx->function_candidate(o_t, r_t) && m.assume(Kind::Function, o_t, r_t);
}

bool Comparer::infer_vtable(u64 o_vt, u64 r_vt) {
  if (!vtables.count(o_vt) || !ctx->symbol_start(r_vt) || !m.assume(Kind::Vtable, o_vt, r_vt)) return false;
  if (m.mode() == Matching::Mode::Explore) vtable(o_vt, r_vt);
  return true;
}

// One address field: the original's target o_t against the rebuild's r_t (`access`: the bytes the instruction reads
// there, 0 when it only takes the address). The rebuilt target is first given a key, what it stands for, trying in
// order (each step only while the ones before have not decided):
//   1. __ImageBase and imports compare directly (an import by its DLL and name or ordinal);
//   2. resolve(): an annotation's original address, the original's name for the symbol, a constant or string literal
//      by name, an RTTI or EH type by name, a local static the pairing has bound, or an offset into a resolved symbol;
//   3. one of several names at r_t naming o_t (ICF-folded symbols) stands for o_t;
//   4. a local static the votes did not place stands for o_t's when it fits there (bind_local);
//   5. an unresolved function stands for o_t when its code compares equal (infer_function);
//   6. an unresolved vtable stands for o_t when its slots and RTTI compare equal (infer_vtable);
//   7. inside a compiler constant or string literal: the literal, with o_t moved back by the same offset;
//   8. a slot past the first of an unresolved vtable: the vtable, inferred as in 6 and compared by its own slots (its
//      symbol's span can run on over whatever the link put next);
//   9. inside unresolved read-only data: its containing object stands for o_t's object (infer_data).
// Steps 4, 5, 6, 8 and 9 are guesses (Matching): assumed while exploring, answered by the matching when judging.
// Then the key decides what is compared: a constant or string by its bytes (and the bytes the instruction reads from
// it), a type descriptor by name, ThrowInfo by its catchable types, a vbtable by its offsets; a key that is not o_t is
// a reference problem, unless it is one past the end of the data object before (a loop bound). A key that is o_t
// compares what is there: a vtable's slots and RTTI, nothing more for code (each function is compared on its own), the
// bytes read for an access, else the object's initial contents.
std::optional<Problem> Comparer::ref(u64 o_t, u64 r_t, int access) {
  if (o_t == O->base && r_t == R->base) return std::nullopt;  // __ImageBase
  auto oi = O->imports.find(o_t);
  auto ri = R->imports.find(r_t);
  if (oi != O->imports.end() || ri != R->imports.end()) {
    const Import* a = oi == O->imports.end() ? nullptr : &oi->second;
    const Import* b = ri == R->imports.end() ? nullptr : &ri->second;
    if ((a == nullptr) == (b == nullptr) && (!a || *a == *b)) return std::nullopt;
    return Problem{Category::Reference, "import " + imp_str(a) + " vs " + imp_str(b)};
  }
  Key key = resolve(r_t);
  if (!key.is_va(o_t) && is_alternate(o_t, r_t)) key = Key::of_va(o_t);
  if (key.kind == Key::UNRESOLVED || (!key.is_va(o_t) && ctx->local_base(r_t).has_value())) {
    if (bind_local(o_t, r_t)) key = Key::of_va(o_t);
  }
  if (key.kind == Key::UNRESOLVED && O->executable(o_t) && infer_function(o_t, r_t)) key = Key::of_va(o_t);
  if (key.kind == Key::UNRESOLVED && vtables.count(o_t) && infer_vtable(o_t, r_t)) key = Key::of_va(o_t);
  u64 o_at = o_t, r_at = r_t;
  std::optional<std::pair<u64, Key>> lit;
  if (key.kind == Key::UNRESOLVED) lit = ctx->literal_at(r_t);
  if (lit) {
    r_at = lit->first;
    key = lit->second;
    o_at = o_t - (r_t - r_at);
  }
  if (key.kind == Key::UNRESOLVED && !O->executable(o_t) && !O->writable(o_t)) {
    if (auto base = ctx->containing(r_t)) {
      u64 off = r_t - *base, o_base = o_t - off;
      if (is_vtable_slot(o_base, off) && infer_vtable(o_base, *base)) return vtable(o_base, *base);
      if (infer_data(o_base, *base)) key = Key::of_va(o_t);
    }
  }
  // a literal is read-only data: the original reading a global with the same bytes is another program
  if ((key.kind == Key::CONST || key.kind == Key::STR) && O->writable(o_t))
    return Problem{Category::Reference, hex(o_t) + " is writable data, not " + std::string(key.name.substr(0, 40))};
  if (key.kind == Key::CONST) {
    i64 n = constant_size(key.name);
    if (!n) n = access ? access : 4;
    if (O->bytes(o_at, n) != R->bytes(r_at, n) || (lit && !same_read(o_t, r_t, access, r_at + u64(n))))
      return Problem{Category::Data, "constant " + std::string(key.name) + " differs from " + hex(o_t)};
    return std::nullopt;
  }
  if (key.kind == Key::STR) {
    bool wide = key.wide();
    Bytes rs = R->cstring(r_at, wide);
    if (O->cstring(o_at, wide) != rs || (lit && !same_read(o_t, r_t, access, r_at + rs.size(), wide)))
      return Problem{Category::Data, "string " + std::string(key.name.substr(0, 40)) + " differs from " + hex(o_t)};
    return std::nullopt;
  }
  if (key.kind == Key::TD) {
    bool same = same_names({{type_name(*O, o_at), type_name(*R, r_at)}});
    if (same) return std::nullopt;
    return Problem{Category::Reference, hex(o_t) + " vs " + std::string(key.name)};
  }
  if (key.kind == Key::TI && o_at == o_t && r_at == r_t) return throw_info_cmp(o_t, r_t, key.name);
  if (key.kind == Key::VBT && o_at == o_t && r_at == r_t) {
    u64 n = ctx->span(r_t);
    size_t i = R->reloc_lower_bound(r_t);
    if (i < R->reloc_sorted.size() && R->reloc_sorted[i] < r_t + n) n = R->reloc_sorted[i] - r_t;
    if (O->bytes(o_t, i64(n)) == R->bytes(r_t, i64(n))) return std::nullopt;
    return Problem{Category::Data, "vbtable " + std::string(key.name.substr(0, 40)) + " differs from " + hex(o_t)};
  }
  if (!key.is_va(o_t)) {
    if (!access && !O->executable(o_t) && !ctx->orig_named(o_t)) {
      auto e = ctx->end_of_previous(r_t);
      if (e && *e == o_t) return std::nullopt;  // one past the end of the data object before (a loop bound)
    }
    return Problem{Category::Reference,
                   hex(o_t) + " vs " + (key.kind == Key::UNRESOLVED ? std::string(key.name) : hex(key.va))};
  }
  if (vtables.count(o_t)) return vtable(o_t, r_t);
  if (O->executable(o_t)) return std::nullopt;  // code: identity; callees are verified on their own
  if (access) return accessed(o_t, r_t, access);
  return rodata(o_t, r_t);  // address taken: the object's initial contents, writable or not
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
      if (!O->has_reloc(u64(i64(o_t) + (p - i64(r_t)))))
        return Problem{Category::Data,
                       std::to_string(n) + " bytes at " + hex(o_t) + " differ: a pointer only in the rebuild"};
      ptrs.push_back(p - i64(r_t));
    }
  }
  for (i64 off : ptrs) {
    i64 lo = std::max<i64>(off, 0), hi = std::min<i64>(off + 8, n);
    mask(a, lo, hi);
    mask(b, lo, hi);
  }
  if (a != b) return Problem{Category::Data, std::to_string(n) + " bytes at " + hex(o_t) + " differ"};
  for (i64 off : ptrs) {
    u64 o_p = O->u64_at(u64(i64(o_t) + off)), r_p = R->u64_at(u64(i64(r_t) + off));
    if (infer_data(o_p, r_p)) continue;
    auto p = ref(o_p, r_p, 0);
    if (p) {
      std::string offs = off < 0 ? hex_signed(off) : "+" + hex(u64(off));
      return Problem{p->category, "pointer at " + hex(o_t) + offs + ": " + p->detail};
    }
  }
  return std::nullopt;
}

namespace {
Problems as_problems(std::optional<Problem> p) { return p ? Problems{std::move(*p)} : Problems{}; }
std::optional<Problem> first(const Problems& ps) { return ps.empty() ? std::nullopt : std::optional<Problem>(ps[0]); }
}  // namespace

// read-only data and vtables can point at each other: met again while it is being compared, a unit holds (Matching)
std::optional<Problem> Comparer::rodata(u64 o_t, u64 r_t) {
  return first(m.unit(Kind::Data, o_t, r_t, [&] { return as_problems(rodata_body(o_t, r_t)); }));
}

std::optional<Problem> Comparer::rodata_body(u64 o_t, u64 r_t) {
  u64 n = ctx->span(r_t);
  Bytes all(R->bytes(r_t, i64(n)));
  i64 want = i64(rstrip_char(all, '\0').size());
  size_t lo = R->reloc_lower_bound(r_t), hi = R->reloc_lower_bound(r_t + n);
  std::vector<i64> ptrs;
  for (size_t i = lo; i < hi; ++i) ptrs.push_back(i64(R->reloc_sorted[i] - r_t));
  // the original object's bytes up to its known end, within the rebuilt span. Not for an address inside a symbol with
  // nothing but zeros after it: that is an end pointer (a loop bound), and the original has the next object there
  bool end_pointer = want == 0 && !ctx->symbol_start(r_t);
  i64 known = end_pointer ? 0 : std::min<i64>(i64(n), i64(ctx->orig_object_end(o_t)) - i64(o_t));
  i64 size = std::max<i64>(want, known);
  for (i64 off : ptrs)
    if (off < want) size = std::max(size, off + 8);
  std::vector<i64> kept;
  for (i64 off : ptrs)
    if (off < size) kept.push_back(off);
  Bytes a(O->bytes(o_t, size)), b(R->bytes(r_t, size));
  for (i64 off : kept) {
    mask(a, off, off + 8);
    mask(b, off, off + 8);
  }
  std::optional<Problem> res;
  std::string what = (O->writable(o_t) || R->writable(r_t)) ? "initial data" : "read-only data";
  if (a != b) res = Problem{Category::Data, what + " at " + hex(o_t) + " differs"};
  if (!res) {
    // a pointer only in the original: its relocations in the range are more than the rebuilt pointers kept
    size_t o_lo = O->reloc_lower_bound(o_t), o_hi = O->reloc_lower_bound(o_t + u64(size));
    if (o_hi - o_lo > kept.size())
      res = Problem{Category::Data, what + " at " + hex(o_t) + ": +" + hex(O->reloc_sorted[o_lo] - o_t) +
                                        " or after is a pointer only in the original"};
  }
  if (!res) {
    for (i64 off : kept) {
      if (!O->has_reloc(o_t + u64(off))) {
        res = Problem{Category::Data,
                      what + " at " + hex(o_t) + ": +" + hex(u64(off)) + " is a pointer only in the rebuild"};
        break;
      }
      u64 o_p = O->u64_at(o_t + u64(off)), r_p = R->u64_at(r_t + u64(off));
      if (infer_data(o_p, r_p)) continue;
      auto p = ref(o_p, r_p, 0);
      if (p) {
        res = Problem{p->category, "pointer at " + hex(o_t) + "+" + hex(u64(off)) + ": " + p->detail};
        break;
      }
    }
  }
  return res;
}

bool Comparer::infer_data(u64 o_t, u64 r_t) {
  if (vtables.count(o_t)) return false;  // by its slots and RTTI (infer_vtable): its bytes do not hold the RTTI
  // a local static is placed by its own rule (bind_local)
  if (ctx->local_base(r_t) || resolve(r_t).kind != Key::UNRESOLVED) return false;
  if (!ctx->symbol_start(r_t) || O->writable(o_t) || R->writable(r_t) || O->executable(o_t) || R->executable(r_t))
    return false;
  if (!O->flags(o_t)) return false;
  auto rb = R->bytes(r_t, i64(ctx->span(r_t)));
  // all zeros: nothing to tell this object from any other zero-filled one
  if (rb.find_first_not_of('\0') == std::string_view::npos) return false;
  if (!m.assume(Kind::Data, o_t, r_t)) return false;
  if (m.mode() == Matching::Mode::Explore) rodata(o_t, r_t);
  return true;
}

std::optional<Problem> Comparer::throw_info_cmp(u64 o_t, u64 r_t, std::string_view name) {
  Signature os = signature(*O, THROW_INFO, o_t), rs = signature(*R, THROW_INFO, r_t);
  if (!same_signature(os, rs))
    return Problem{Category::Reference, hex(o_t) + " vs " + std::string(name) + ": catchable types differ"};
  // the destructor, then each catchable type's copy constructor
  for (size_t i = 0; i < std::min(os.functions.size(), rs.functions.size()); ++i) {
    u64 a = os.functions[i], b = rs.functions[i];
    if (bool(a) != bool(b))
      return Problem{Category::Reference,
                     hex(o_t) + " vs " + std::string(name) + ": function " + hex(a) + " vs " + hex(b)};
    if (a) {
      auto p = ref(a, b, 0);
      if (p) return Problem{p->category, std::string(name) + ": " + p->detail};
    }
  }
  return std::nullopt;
}

std::optional<Problem> Comparer::vtable(u64 o_vt, u64 r_vt) {
  return first(m.unit(Kind::Vtable, o_vt, r_vt, [&] { return as_problems(vtable_body(o_vt, r_vt)); }));
}

std::optional<Problem> Comparer::vtable_body(u64 o_vt, u64 r_vt) {
  std::optional<Problem> res;
  const auto& slots = vtables.at(o_vt);
  for (size_t i = 0; i < slots.size(); ++i) {
    u64 s = slots[i];
    u64 r_s = R->u64_at(r_vt + 8 * i);
    Key got = resolve(r_s);
    if (got.is_va(s) || is_alternate(s, r_s)) continue;
    if (got.kind == Key::UNRESOLVED && O->executable(s) && infer_function(s, r_s)) continue;
    res = Problem{Category::Vtable,
                  "slot " + std::to_string(i) + " of " + hex(o_vt) + ": " + hex(s) + " vs " + got.text()};
    break;
  }
  if (!res && !same_signature(rtti_signature(*O, O->u64_at(o_vt - 8)), rtti_signature(*R, R->u64_at(r_vt - 8))))
    res = Problem{Category::Vtable, "RTTI of " + hex(o_vt) + " differs"};
  return res;
}

}  // namespace verifier
