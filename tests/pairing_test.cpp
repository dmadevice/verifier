// Pairing: annotations, folded and stub annotations, inference, local statics, addends.
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

Findings folded_annotations() {
  Original orig;
  FakeRebuilt reb;
  reb.symbols = Symbols({{0x100, "?A@@YAXXZ"}, {0x100, "?B@@YAXXZ"}, {0x200, "?C@@YAXXZ"}});
  reb.fake.qualified = [](std::string_view n) { return std::string(n.substr(1, 1)); };
  std::map<std::string, u64> m{{"A", 0x100}, {"B", 0x100}, {"C", 0x200}};
  reb.fake.lookup = [m](const std::string& k, auto&, bool) { return fixed_lookup(m, k); };
  std::vector<Annotation> anns = {{Kind::Function, 0x1000, "A", {}, "a.cpp", 1},
                                  {Kind::Function, 0x2000, "B", {}, "b.cpp", 1},
                                  {Kind::Function, 0x3000, "C", {}, "c.cpp", 1}};
  Pairing p(orig, reb, anns);
  auto a1 = p.alternates(0x100), a2 = p.alternates(0x200);
  bool ok = std::set<u64>(a1.begin(), a1.end()) == std::set<u64>{0x1000, 0x2000} && a2.empty();
  return bad_if(!ok, "alternates", "wrong alternates");
}

Findings stub_pairing() {
  Original orig;
  FakeRebuilt reb;
  reb.symbols = Symbols({{0x100, "sub_1000"}, {0x200, "A"}});
  std::map<std::string, u64> m{{"sub_1000", 0x100}, {"A", 0x200}};
  reb.fake.lookup = [m](const std::string& k, auto&, bool) { return fixed_lookup(m, k); };
  Pairing p(orig, reb, {{Kind::Stub, 0x1000, "sub_1000", {}, "s.cpp", 1}, {Kind::Function, 0x2000, "A", {}, "a.cpp", 1}});
  bool ok = p.paired_o == std::vector<u64>{0x2000};
  return bad_if(!ok, "paired", "stub/function paired wrongly");
}

Findings failed_inference() {
  Side o(0), r(0x240);
  struct Fns {
    u64 A, X, G, F;
  } fo{}, fr{};
  for (auto [s, f, imm] : {std::tuple<Side*, Fns*, u32>{&o, &fo, 1}, {&r, &fr, 2}}) {
    f->A = s->reserve(TEXT, 16);
    f->X = s->put(RDATA, Bytes(8, '\0'), 8);
    s->relocs.push_back(f->X);
    s->write(f->X, le64b(f->A));
    s->write(f->A, lea_rcx(f->A, f->X) + "\xb8" + le32b(imm) + "\xc3");
    f->G = s->reserve(TEXT, 16);
    s->write(f->G, call(f->G, f->A) + "\xc3");
    f->F = s->reserve(TEXT, 16);
    s->write(f->F, lea_rcx(f->F, f->X) + "\xc3");
  }
  Original orig;
  for (auto [va, size] : {std::pair<u64, u64>{fo.A, 13}, {fo.G, 6}, {fo.F, 8}})
    orig.functions.set(IdaFunction{va, size, "", false, false});
  FakeRebuilt reb;
  reb.symbols = symbols_at({fr.A, fr.G, fr.F, fr.X});
  std::map<u64, u64> rsize{{fr.A, 13}, {fr.G, 6}, {fr.F, 8}};
  reb.fake.extent = [rsize](u64 va) { return va + rsize.at(va); };
  std::map<std::string, u64> m{{"X", fr.X}, {"G", fr.G}, {"F", fr.F}};
  reb.fake.lookup = [m](const std::string& k, auto&, bool) { return fixed_lookup(m, k); };
  Pairing p(orig, reb,
            {{Kind::Global, fo.X, "X", {}, "x.cpp", 1},
             {Kind::Function, fo.G, "G", {}, "g.cpp", 1},
             {Kind::Function, fo.F, "F", {}, "f.cpp", 1}});
  Image O = o.image(), R = r.image();
  struct InferOnly : ComparerContext {  // the pairing's inference, nothing else known
    Pairing& p;
    explicit InferOnly(Pairing& x) : p(x) {}
    bool infer(u64 a, u64 b) override { return p.infer(a, b); }
  } infer_only(p);
  p.use(std::make_unique<Comparer>(&O, &R, [&p](u64 t) { return p.resolve_symbol(t); }, nullptr, nullptr, &infer_only));
  auto g = p.cmp->function(fo.G, fo.G + 6, fr.G, fr.G + 6);
  auto f = p.cmp->function(fo.F, fo.F + 8, fr.F, fr.F + 8);
  return g.empty() ? Findings{{"setup", "G should differ"}} : f;
}

// inference pairs one rebuilt function with each original: G and H both call A in the original, and two copies of it
// in the rebuild (A1, A2); once A1 is inferred to be A, H's call to A2 is a reference problem
Findings inference_one_to_one() {
  Side o(0), r(0x240);
  Bytes body = unhex("b801000000c3");
  u64 oa = o.put(TEXT, body, 16), og = o.reserve(TEXT, 16), oh = o.reserve(TEXT, 16);
  o.write(og, call(og, oa) + "\xc3");
  o.write(oh, call(oh, oa) + "\xc3");
  u64 ra1 = r.put(TEXT, body, 16), ra2 = r.put(TEXT, body, 16), rg = r.reserve(TEXT, 16), rh = r.reserve(TEXT, 16);
  r.write(rg, call(rg, ra1) + "\xc3");
  r.write(rh, call(rh, ra2) + "\xc3");
  Original orig;
  for (auto [va, size] : {std::pair<u64, u64>{oa, 6}, {og, 6}, {oh, 6}})
    orig.functions.set(IdaFunction{va, size, "", false, false});
  FakeRebuilt reb;
  reb.symbols = symbols_at({ra1, ra2, rg, rh});
  reb.fake.extent = [](u64 va) { return va + 6; };
  std::map<std::string, u64> m{{"G", rg}, {"H", rh}};
  reb.fake.lookup = [m](const std::string& k, auto&, bool) { return fixed_lookup(m, k); };
  Pairing p(orig, reb, {{Kind::Function, og, "G", {}, "g.cpp", 1}, {Kind::Function, oh, "H", {}, "h.cpp", 1}});
  Image O = o.image(), R = r.image();
  struct InferOnly : ComparerContext {
    Pairing& p;
    explicit InferOnly(Pairing& x) : p(x) {}
    bool infer(u64 a, u64 b) override { return p.infer(a, b); }
  } infer_only(p);
  p.use(std::make_unique<Comparer>(&O, &R, [&p](u64 t) { return p.resolve_symbol(t); }, nullptr, nullptr, &infer_only));
  auto g = p.cmp->function(og, og + 6, rg, rg + 6);
  auto h = p.cmp->function(oh, oh + 6, rh, rh + 6);
  return g.empty() ? h : Findings{{"setup", "G should match"}};
}

// a leaf with no .pdata: the rebuild's extent reaches the next symbol, over the nop before a table, and the original's
// stops at the last ret. The report gives both the same size
Findings padded_leaf_sizes() {
  Side o(0), r(0x240);
  Bytes code = unhex("b801000000c3");
  u64 of = o.put(TEXT, code + unhex("6690"));
  u64 rf = r.put(TEXT, code + unhex("6690"));
  FakeRun run;
  run.O = o.image();
  run.R = r.image();
  run.orig.functions.set(IdaFunction{of, code.size(), "", false, false});
  run.reb.symbols = symbols_at({rf, rf + code.size() + 2});
  std::map<std::string, u64> m{{"F", rf}};
  run.reb.fake.lookup = [m](const std::string& k, auto&, bool) { return fixed_lookup(m, k); };
  Annotation ann{Kind::Function, of, "F", {}, "f.cpp", 1};
  run.start({ann});
  Out out;
  Result res = evaluate(ann, run.orig, run.reb, *run.p, *run.c, ".", false, out);
  Findings bad;
  if (res.status != Status::Match) bad.push_back({"status", std::string(status_name(res.status))});
  if (res.osize != i64(code.size()) || res.rsize != res.osize)
    bad.push_back({"sizes", std::to_string(res.osize) + "/" + std::to_string(res.rsize)});
  return bad;
}

Findings prebound_static(bool owner_first) {
  Side o(0), r(0x240);
  struct S {
    u64 sf, sg, F, G;
  } so{}, sr{};
  for (auto [s, x] : {std::pair<Side*, S*>{&o, &so}, {&r, &sr}}) {
    x->sf = s->put(DATA, Bytes(4, '\0'), 4);
    x->sg = s->put(DATA, Bytes(4, '\0'), 4);
    x->F = s->reserve(TEXT, 16);
    x->G = s->reserve(TEXT, 16);
    s->write(x->G, mov_eax_g(x->G, x->sg) + "\xc3");
  }
  o.write(so.F, mov_eax_g(so.F, so.sf) + "\xc3");
  r.write(sr.F, mov_eax_g(sr.F, sr.sg) + "\xc3");
  FakeRun run;
  run.O = o.image();
  run.R = r.image();
  for (u64 va : {so.F, so.G}) run.orig.functions.set(IdaFunction{va, 7, "", false, false});
  auto& reb = run.reb;
  reb.symbols = symbols_at({sr.F, sr.G, sr.sf, sr.sg});
  reb.local_statics = {sr.sf, sr.sg};
  reb.static_owner = {{sr.sf, std::set<u64>{sr.F}}, {sr.sg, std::set<u64>{sr.G}}};
  reb.fake.extent = [](u64 va) { return va + 7; };
  std::map<std::string, u64> m{{"F", sr.F}, {"G", sr.G}};
  reb.fake.lookup = [m](const std::string& k, auto&, bool) { return fixed_lookup(m, k); };
  reb.fake.local_base = [sr](u64 t) -> std::optional<std::pair<u64, u64>> {
    for (u64 b : {sr.sf, sr.sg})
      if (b <= t && t < b + 4) return std::make_pair(b, t - b);
    return std::nullopt;
  };
  reb.fake.span = [](u64) { return u64(16); };
  run.start({{Kind::Function, so.F, "F", {}, "f.cpp", 1}, {Kind::Function, so.G, "G", {}, "g.cpp", 1}});
  std::vector<std::pair<u64, u64>> order;
  if (owner_first) order.emplace_back(so.G, sr.G);
  order.emplace_back(so.F, sr.F);
  Findings probs;
  for (auto [of, rf] : order) probs = run.c->function(of, of + 7, rf, rf + 7);
  return probs;
}

Findings consensus_static() {
  Side o(0), r(0x240);
  u64 ox = o.put(DATA, Bytes(8, '\0'), 16), oy = o.put(DATA, Bytes(8, '\0'), 16);
  u64 rs = r.put(DATA, Bytes(8, '\0'), 16);
  std::vector<std::pair<std::string, std::pair<u64, u64>>> fns;
  for (const char* n : {"w", "a", "b"}) {
    u64 fo = o.reserve(TEXT, 16), fr = r.reserve(TEXT, 16);
    o.write(fo, mov_eax_g(fo, std::string(n) == "w" ? oy : ox) + "\xc3");
    r.write(fr, mov_eax_g(fr, rs) + "\xc3");
    fns.push_back({n, {fo, fr}});
  }
  FakeRun run;
  run.O = o.image();
  run.R = r.image();
  auto& reb = run.reb;
  std::map<std::string, u64> m;
  std::vector<Annotation> anns;
  std::vector<u64> vas;
  for (auto& [n, f] : fns) {
    run.orig.functions.set(IdaFunction{f.first, 7, "", false, false});
    vas.push_back(f.second);
    m[n] = f.second;
    anns.push_back({Kind::Function, f.first, n, {}, n + ".cpp", 1});
  }
  vas.push_back(rs);
  reb.symbols = symbols_at(vas);
  reb.local_statics = {rs};
  reb.static_owner = {{rs, std::nullopt}};
  reb.fake.extent = [](u64 va) { return va + 7; };
  reb.fake.lookup = [m](const std::string& k, auto&, bool) { return fixed_lookup(m, k); };
  reb.fake.local_base = [rs](u64 t) -> std::optional<std::pair<u64, u64>> {
    if (rs <= t && t < rs + 8) return std::make_pair(rs, t - rs);
    return std::nullopt;
  };
  reb.fake.span = [](u64) { return u64(16); };
  run.start(anns);
  std::map<std::string, bool> got;
  for (auto& [n, f] : fns) got[n] = !run.c->function(f.first, f.first + 7, f.second, f.second + 7).empty();
  bool ok = got == std::map<std::string, bool>{{"w", true}, {"a", false}, {"b", false}};
  return bad_if(!ok, "binding", "differs");
}

Findings folded_original(bool same_code) {
  Side o(0), r(0x240);
  u64 oo = o.reserve(TEXT, 16);
  o.write(oo, "\x8b\x41\x18\xc3");
  u64 ra = r.reserve(TEXT, 16);
  r.write(ra, "\x8b\x41\x18\xc3");
  u64 rb = r.reserve(TEXT, 16);
  r.write(rb, same_code ? "\x8b\x41\x18\xc3" : "\x8b\x41\x1c\xc3");
  u64 oG = o.reserve(TEXT, 16);
  o.write(oG, call(oG, oo) + "\xc3");
  u64 rG = r.reserve(TEXT, 16);
  r.write(rG, call(rG, rb) + "\xc3");
  FakeRun run;
  run.O = o.image();
  run.R = r.image();
  run.orig.functions.set(IdaFunction{oo, 4, "", false, false});
  run.orig.functions.set(IdaFunction{oG, 6, "", false, false});
  auto& reb = run.reb;
  reb.symbols = symbols_at({ra, rb, rG});
  reb.fake.extent = [rG](u64 va) { return va + (va == rG ? 6 : 4); };
  std::map<std::string, u64> m{{"A", ra}, {"G", rG}};
  reb.fake.lookup = [m](const std::string& k, auto&, bool) { return fixed_lookup(m, k); };
  reb.fake.local_base = [](u64) { return std::optional<std::pair<u64, u64>>(); };
  reb.fake.span = [](u64) { return u64(16); };
  run.start({{Kind::Function, oo, "A", {}, "a.cpp", 1}, {Kind::Function, oG, "G", {}, "g.cpp", 1}});
  return run.c->function(oG, oG + 6, rG, rG + 6);
}

Findings addend_across_annotation(u64 off) {
  Side o(0), r(0x240);
  u64 og = o.put(DATA, Bytes(0x20, '\0'), 16), oy = o.put(DATA, Bytes(4, '\0'), 16);
  u64 rg = r.put(DATA, Bytes(0x40, '\0'), 16), ry = r.put(DATA, Bytes(4, '\0'), 16);
  Original orig;
  FakeRebuilt reb;
  reb.symbols = Symbols({{rg, "?g@@3HA"}, {ry, "?y@@3HA"}});
  reb.fake.qualified = [](std::string_view n) { return std::string(n.substr(1, 1)); };
  std::map<std::string, u64> m{{"g", rg}, {"y", ry}};
  reb.fake.lookup = [m](const std::string& k, auto&, bool) { return fixed_lookup(m, k); };
  reb.fake.local_base = [](u64) { return std::optional<std::pair<u64, u64>>(); };
  Pairing p(orig, reb, {{Kind::Global, og, "g", {}, "g.cpp", 1}, {Kind::Global, oy, "y", {}, "y.cpp", 1}});
  p.use(std::make_unique<Comparer>(nullptr, nullptr, [&p](u64 t) { return p.resolve(t); }));
  Key got = p.resolve(rg + off);
  return bad_if(!got.is_va(og + off), "reference", "g+" + hex(off) + " resolves to " + got.text());
}

// a symbol does not run on into the next section: past its section's end, an address is no addend to it
Findings addend_across_sections() {
  Side o(0), r(0x240);
  u64 og = o.put(RDATA, Bytes(0x20, '\0'), 16);
  u64 rg = r.put(RDATA, Bytes(0x20, '\0'), 16);
  Original orig;
  FakeRebuilt reb;
  reb.img = r.image();
  reb.symbols = Symbols({{rg, "?g@@3HA"}});
  reb.fake.qualified = [](std::string_view n) { return std::string(n.substr(1, 1)); };
  std::map<std::string, u64> m{{"g", rg}};
  reb.fake.lookup = [m](const std::string& k, auto&, bool) { return fixed_lookup(m, k); };
  reb.fake.local_base = [](u64) { return std::optional<std::pair<u64, u64>>(); };
  Pairing p(orig, reb, {{Kind::Global, og, "g", {}, "g.cpp", 1}});
  p.use(std::make_unique<Comparer>(nullptr, nullptr, [&p](u64 t) { return p.resolve(t); }));
  Findings bad;
  if (!p.resolve(rg + 0x10).is_va(og + 0x10)) bad.push_back({"reference", "inside the symbol"});
  u64 last = BASE + DATA - 1, past = BASE + DATA + 8;
  if (!p.resolve(last).is_va(og + (last - rg))) bad.push_back({"reference", "the section's last byte"});
  if (p.resolve(past).kind != Key::UNRESOLVED) bad.push_back({"reference", "resolves in another section"});
  if (reb.containing(past)) bad.push_back({"containing", "a symbol of another section"});
  return bad;
}

}  // namespace

void add_pairing_cases(Cases& cases) {
  cases.insert(cases.end(), {
      {"folded annotations", nullptr, folded_annotations},
      {"stub leaves its original open", nullptr, stub_pairing},
      {"failed inference taken back", "reference", failed_inference},
      {"inference one-to-one", "reference", inference_one_to_one},
      {"padded leaf, same size reported", nullptr, padded_leaf_sizes},
      {"other static, owner compared later", "reference", [] { return prebound_static(false); }},
      {"other static, owner compared first", "reference", [] { return prebound_static(true); }},
      {"local static paired by consensus", nullptr, consensus_static},
      {"callee folded in the original, same code", nullptr, [] { return folded_original(true); }},
      {"callee folded in the original, other code", "reference", [] { return folded_original(false); }},
      {"addend inside an annotated object", nullptr, [] { return addend_across_annotation(0x10); }},
      {"addend reaching another annotation", "reference", [] { return addend_across_annotation(0x20); }},
      {"addend stays in its section", nullptr, addend_across_sections},
  });
}

}  // namespace verifier::test
