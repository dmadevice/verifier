// The comparison: build hashes, GLOBAL bytes, literals, data extents, pointers, table cycles, unwind.
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <random>
#include <set>
#include <string>
#include <vector>

#include "support.hpp"

namespace verifier::test {

namespace {

Findings build_hashes() {
  Comparer c(nullptr, nullptr, [](u64) { return Key::named(Key::UNRESOLVED, ""); });
  Bytes a = ".?AVX@?A0x11111111@@", b = ".?AVX@?A0x22222222@@";
  auto rtti_of = [](const Bytes& name, u32 off) {
    Rtti r;
    r.present = true;
    r.name = name;
    r.off = off;
    return r;
  };
  Findings bad;
  if (!c.same_names({{a, b}}) || !c.same_rtti(rtti_of(a, 1), rtti_of(b, 1)))
    bad.push_back({"hash", "same name, other hash"});
  if (c.same_names({{a, ".?AVX@?A0x33333333@@"}}) || c.same_names({{".?AVX@?A0x44444444@@", b}}))
    bad.push_back({"hash", "a hash paired twice"});
  if (c.same_rtti(rtti_of(a, 1), rtti_of(b, 2)) || c.same_names({{".?AVY@?A0x55555555@@", ".?AVZ@?A0x66666666@@"}}))
    bad.push_back({"hash", "other value or name"});
  if (c.same_rtti(rtti_of(".?AVW@?A0x99999999@@", 1), rtti_of(".?AVW@?A0xaaaaaaaa@@", 2)) ||
      !c.same_names({{".?AVW@?A0x99999999@@", ".?AVW@?A0xbbbbbbbb@@"}}))
    bad.push_back({"hash", "a failed comparison left a pairing behind"});
  // a hash spelled the same on both sides is paired with itself like any other, in either order
  for (bool same_first : {true, false}) {
    Comparer d(nullptr, nullptr, [](u64) { return Key::named(Key::UNRESOLVED, ""); });
    Bytes s = "F<lambda_cc>", t = "F<lambda_dd>";
    bool first = same_first ? d.same_names({{s, s}}) : d.same_names({{s, t}});
    bool second = same_first ? d.same_names({{s, t}}) : d.same_names({{s, s}});
    if (!first || second) bad.push_back({"hash", std::string("a hash paired twice, same spelling ") + (same_first ? "first" : "second")});
  }
  return bad;
}

Findings global_bytes() {
  Side o(0), r(0x240);
  u64 oa = o.put(RDATA, Bytes("STANDARD\0", 9)), ob = o.put(RDATA, Bytes("EXPANDED\0", 9)),
      ow = o.put(DATA, Bytes("\1\0\0\0", 4));
  u64 ra = r.put(RDATA, Bytes("STANDARD\0", 9)), rb = r.put(RDATA, Bytes("EXPANDED\0", 9)),
      rw = r.put(DATA, Bytes("\2\0\0\0", 4));
  Image O = o.image(), R = r.image();
  std::map<std::string, u64> names{{"g_std", ra}, {"g_exp", rb}, {"g_w", rw}};
  std::vector<Annotation> anns = {{Kind::Global, oa, "g_std", {}, "a.cpp", 1},
                                  {Kind::Global, oa, "g_exp", {}, "a.cpp", 2},
                                  {Kind::Global, ow, "g_w", {}, "a.cpp", 3},
                                  {Kind::Global, ob, "g_gone", {}, "a.cpp", 4},
                                  {Kind::Function, ob, "g_std", {}, "a.cpp", 5}};
  std::unordered_map<u64, u64> reb_to_orig{{ra, oa}, {rb, oa}, {rw, ow}};
  struct Spans : ComparerContext {
    u64 span(u64) const override { return 16; }
  } spans;
  Comparer c(
      &O, &R,
      [&](u64 t) {
        auto it = reb_to_orig.find(t);
        return it != reb_to_orig.end() ? Key::of_va(it->second) : Key::named(Key::UNRESOLVED, "");
      },
      nullptr, nullptr, &spans);
  auto lookup = [&](const std::string& n) {
    auto it = names.find(n);
    return it == names.end() ? std::vector<u64>() : std::vector<u64>{it->second};
  };
  std::vector<std::string> got;
  auto orig_of = [&](u64 rva) -> std::optional<u64> {
    auto it = reb_to_orig.find(rva);
    return it == reb_to_orig.end() ? std::nullopt : std::optional<u64>(it->second);
  };
  for (auto& g : check_globals(anns, lookup, orig_of, c)) got.push_back(g.ann->name);
  return bad_if(got != std::vector<std::string>{"g_exp"}, "globals", "reported " + join(got, ","));
}

// a compiler constant or string literal pairs with read-only data only: the original reading a global that holds the
// same bytes is another program (the global can change)
Findings literal_vs_global(bool string) {
  Side o(0), r(0x240);
  Bytes v = string ? Bytes("abc\0", 4) : unhex("0000803f");
  u64 og = o.put(DATA, v, 4), rk = r.put(RDATA, v, 4);
  u64 of = o.reserve(TEXT, 16), rf = r.reserve(TEXT, 16);
  o.write(of, mov_eax_g(of, og) + "\xc3");
  r.write(rf, mov_eax_g(rf, rk) + "\xc3");
  Image O = o.image(), R = r.image();
  Key k = string ? Key::named(Key::STR, "??_C@_03abc@") : Key::named(Key::CONST, "__real@3f800000");
  Comparer c(&O, &R, [&](u64 t) { return t == rk ? k : Key::named(Key::UNRESOLVED, hex(t)); });
  return c.function(of, of + 7, rf, rf + 7);
}

// read-only data whose original extent is known (from its padding): compared to that end, so a table cut short
// ({1,2,3,4} vs {1,2,3,0}) differs, either way round. Without the extent only the rebuilt nonzero bytes are compared:
// past them the original's bytes may as well be the next object, which the rebuild put after its padding
Findings short_table(bool rebuilt_short) {
  Side o(0), r(0x240);
  Bytes full = unhex("01020304"), cut = unhex("01020300");
  u64 ot = o.put(RDATA, rebuilt_short ? full : cut, 16), rt = r.put(RDATA, rebuilt_short ? cut : full, 16);
  u64 of = o.reserve(TEXT, 16), rf = r.reserve(TEXT, 16);
  o.write(of, lea_rcx(of, ot) + "\xc3");
  r.write(rf, lea_rcx(rf, rt) + "\xc3");
  Image O = o.image(), R = r.image();
  struct Spans : ComparerContext {
    u64 span(u64) const override { return 16; }
    u64 orig_object_end(u64 t) const override { return t + 4; }
  } spans;
  Comparer c(
      &O, &R, [&](u64 t) { return t == rt ? Key::of_va(ot) : Key::named(Key::UNRESOLVED, hex(t)); }, nullptr, nullptr,
      &spans);
  return c.function(of, of + 8, rf, rf + 8);
}

// an end pointer: the address one past a table, which the rebuild's padding holds and the original's next object
// starts at, compares nothing (the original object's end being known)
Findings end_pointer() {
  Side o(0), r(0x240);
  u64 ot = o.put(RDATA, unhex("01000000020000000300000004000000"), 16);
  o.put(RDATA, unhex("05000000"), 4);
  u64 rt = r.put(RDATA, unhex("01000000020000000300000004000000") + Bytes(16, '\0'), 16);
  u64 of = o.reserve(TEXT, 16), rf = r.reserve(TEXT, 16);
  o.write(of, lea_rcx(of, ot + 16) + "\xc3");
  r.write(rf, lea_rcx(rf, rt + 16) + "\xc3");
  Image O = o.image(), R = r.image();
  struct Table : ComparerContext {
    u64 ot = 0, rt = 0;
    u64 span(u64 t) const override { return rt + 32 - t; }
    bool symbol_start(u64 t) const override { return t == rt; }
    u64 orig_object_end(u64 t) const override { return t < ot + 16 ? ot + 16 : ot + 20; }
  } table;
  table.ot = ot;
  table.rt = rt;
  Comparer c(
      &O, &R,
      [&](u64 t) {
        return t >= rt && t < rt + 32 ? Key::of_va(ot + (t - rt)) : Key::named(Key::UNRESOLVED, hex(t));
      },
      nullptr, nullptr, &table);
  return c.function(of, of + 8, rf, rf + 8);
}

// a pointer only in the original: the rebuilt table holds the same eight bytes as a plain number
Findings pointer_only_in_original() {
  Side o(0), r(0x240);
  u64 ot = o.reserve(RDATA, 16), rt = r.reserve(RDATA, 16);
  u64 v = BASE + DATA;
  o.write(ot, le64b(v));
  r.write(rt, le64b(v));
  o.relocs.push_back(ot);
  u64 of = o.reserve(TEXT, 16), rf = r.reserve(TEXT, 16);
  o.write(of, lea_rcx(of, ot) + "\xc3");
  r.write(rf, lea_rcx(rf, rt) + "\xc3");
  Image O = o.image(), R = r.image();
  struct Spans : ComparerContext {
    u64 span(u64) const override { return 16; }
  } spans;
  Comparer c(
      &O, &R, [&](u64 t) { return t == rt ? Key::of_va(ot) : Key::named(Key::UNRESOLVED, hex(t)); }, nullptr, nullptr,
      &spans);
  return c.function(of, of + 8, rf, rf + 8);
}

// tables that point at each other: A = {&B, &C}, B = {&A}, and C differs. B was found consistent while A was assumed
// to be, so A's failure takes B's success back: a function taking B's address differs whichever is compared first
Findings table_cycle(bool a_first) {
  Side o(0), r(0x240);
  struct Tables {
    u64 A, B, C, FA, FB;
  } to{}, tr{};
  for (auto [s, t, fill] : {std::tuple<Side*, Tables*, char>{&o, &to, 0x11}, {&r, &tr, 0x22}}) {
    t->A = s->reserve(RDATA, 16);
    t->B = s->reserve(RDATA, 16);
    t->C = s->put(RDATA, Bytes(8, fill), 16);
    s->write(t->A, le64b(t->B) + le64b(t->C));
    s->write(t->B, le64b(t->A));
    for (u64 p : {t->A, t->A + 8, t->B}) s->relocs.push_back(p);
    t->FA = s->reserve(TEXT, 16);
    s->write(t->FA, lea_rcx(t->FA, t->A) + "\xc3");
    t->FB = s->reserve(TEXT, 16);
    s->write(t->FB, lea_rcx(t->FB, t->B) + "\xc3");
  }
  Image O = o.image(), R = r.image();
  std::map<u64, u64> to_orig{{tr.A, to.A}, {tr.B, to.B}, {tr.C, to.C}, {tr.FA, to.FA}, {tr.FB, to.FB}};
  struct Spans : ComparerContext {
    u64 span(u64) const override { return 16; }
  } spans;
  Comparer c(
      &O, &R,
      [&](u64 t) {
        auto it = to_orig.find(t);
        return it != to_orig.end() ? Key::of_va(it->second) : Key::named(Key::UNRESOLVED, hex(t));
      },
      nullptr, nullptr, &spans);
  auto fa = [&] { return c.function(to.FA, to.FA + 8, tr.FA, tr.FA + 8); };
  auto fb = [&] { return c.function(to.FB, to.FB + 8, tr.FB, tr.FB + 8); };
  Findings pa = a_first ? fa() : Findings(), pb = fb();
  if (!a_first) pa = fa();
  if (pa.empty()) return {{"setup", "A should differ"}};
  return pb;
}

Findings malformed_unwind() {
  Side o(0), r(0x240);
  u64 fo = 0, fr = 0;
  for (auto [s, f] : {std::pair<Side*, u64*>{&o, &fo}, {&r, &fr}}) {
    *f = s->reserve(TEXT, 16);
    s->write(*f, unhex("4883ec28909090904883c428c3"));
    u32 u = unwind_info(*s);
    s->pdata[*f] = {*f + 8, u};
    Bytes chain_body{char(1 | (4 << 3)), 0, 0, 0};
    chain_body += Bytes(12, '\0');
    u64 chain = s->put(RDATA, chain_body, 4);
    s->write(chain + 4, le32b(u32(*f - BASE)) + le32b(u32(*f + 8 - BASE)) + le32b(u32(chain - BASE)));
    s->pdata[*f + 8] = {*f + 8, u32(chain - BASE)};
  }
  Image O = o.image(), R = r.image();
  auto end = R.extent(fr);
  Comparer c(&O, &R, [](u64 t) { return Key::named(Key::UNRESOLVED, hex(t)); });
  c.unwinds(fo, fo + 13, fr, fr + 13);
  c.unwind_info(R.pdata_at(fr + 8)->unwind, R.pdata_at(fr + 8)->unwind, fo, fo + 13, fr, fr + 13, 0);
  return bad_if(!(end && *end == fr + 8), "extent", end ? hex(*end) : "None");
}

// a read-only table of 5 KB whose address a function takes, and the next symbol after it; with `same` false the
// rebuilt table differs in one byte past its first 4 KB
Findings long_table(bool same) {
  Side o(0), r(0x240);
  Bytes t(0x1400, '\x01'), u = t;
  if (!same) u[0x1200] = '\x02';
  u64 ot = o.put(RDATA, t, 16), rt = r.put(RDATA, u, 16);
  o.put(RDATA, Bytes(16, '\x05'), 16);
  u64 rnext = r.put(RDATA, Bytes(16, '\x05'), 16);
  u64 of = o.reserve(TEXT, 16), rf = r.reserve(TEXT, 16);
  o.write(of, lea_rcx(of, ot) + "\xc3");
  r.write(rf, lea_rcx(rf, rt) + "\xc3");
  FakeRun run;
  run.O = o.image();
  run.R = r.image();
  run.orig.functions.set(IdaFunction{of, 8, "", false, false});
  run.reb.symbols = symbols_at({rf, rt, rnext});
  run.reb.fake.extent = [](u64 va) { return va + 8; };
  std::map<std::string, u64> m{{"F", rf}, {"T", rt}};
  run.reb.fake.lookup = [m](const std::string& k, auto&, bool) { return fixed_lookup(m, k); };
  run.start({{Kind::Function, of, "F", {}, "f.cpp", 1}, {Kind::Global, ot, "T", {}, "t.cpp", 1}});
  return run.c->function(of, of + 8, rf, rf + 8);
}

// a table read through an __ImageBase-relative indexed operand (lea rcx, __ImageBase; mov eax, [rcx+rdx*4+table]):
// with `same` false the rebuilt table's third entry differs
Findings image_relative_table(bool same) {
  Side o(0), r(0x240);
  Bytes t = le32b(1) + le32b(2) + le32b(3) + le32b(4), u = t;
  if (!same) u.replace(8, 4, le32b(9));
  u64 ot = o.put(RDATA, t, 16), rt = r.put(RDATA, u, 16);
  u64 of = o.reserve(TEXT, 16), rf = r.reserve(TEXT, 16);
  auto code = [](u64 f, u64 table) { return lea_rcx(f, BASE) + unhex("8b8491") + le32b(u32(table - BASE)) + "\xc3"; };
  o.write(of, code(of, ot));
  r.write(rf, code(rf, rt));
  Image O = o.image(), R = r.image();
  struct Spans : ComparerContext {
    u64 span(u64) const override { return 16; }
  } spans;
  Comparer c(
      &O, &R, [&](u64 x) { return x == rt ? Key::of_va(ot) : Key::named(Key::UNRESOLVED, hex(x)); }, nullptr, nullptr,
      &spans);
  return c.function(of, of + 15, rf, rf + 15);
}

}  // namespace

void add_compare_cases(Cases& cases) {
  cases.insert(cases.end(), {
      {"build hashes pair one-to-one", nullptr, build_hashes},
      {"GLOBAL bytes checked", nullptr, global_bytes},
      {"constant vs writable global", "reference", [] { return literal_vs_global(false); }},
      {"string vs writable global", "reference", [] { return literal_vs_global(true); }},
      {"rebuilt table cut short", "data", [] { return short_table(true); }},
      {"original table cut short", "data", [] { return short_table(false); }},
      {"pointer only in the original", "data", pointer_only_in_original},
      {"end pointer past a table", nullptr, end_pointer},
      {"table cycle, the failing table first", "data", [] { return table_cycle(true); }},
      {"table cycle, the other first", "data", [] { return table_cycle(false); }},
      {"malformed unwind chain ends", nullptr, malformed_unwind},
      {"table past 4 KB, the same", nullptr, [] { return long_table(true); }},
      {"table past 4 KB, differs late", "data", [] { return long_table(false); }},
      {"image-relative table, the same", nullptr, [] { return image_relative_table(true); }},
      {"image-relative table, a later entry differs", "data", [] { return image_relative_table(false); }},
  });
}

}  // namespace verifier::test
