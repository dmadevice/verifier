// Acceptance tests of the comparison engine:
//   verifier-tests [fixtures.json] [-v]       exit code = number of failures
// Each case in tests/data/fixtures.json is a pair of small synthetic PE images (the original and a rebuild laid
// out at other addresses), the two functions to compare, the symbol mapping the comparer's hooks answer from,
// and the exact problems the comparison must report (none for a MATCH). The cases listed under "other" there are
// written out below (pairing, names, annotation parser, report diff), plus a few unit checks.
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "annotations.hpp"
#include "compare.hpp"
#include "inputs.hpp"
#include "json.hpp"
#include "names.hpp"
#include "pairing.hpp"
#include "report.hpp"
#include "sha256.hpp"
#include "verify.hpp"

#ifndef VERIFIER_FIXTURES
#define VERIFIER_FIXTURES "tests/data/fixtures.json"
#endif

using namespace verifier;
using json::Value;

namespace {

bool verbose = false;

// a name for temporary files no other run uses at the same time
std::string unique_suffix() {
  static int n = 0;
  return std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + "-" + std::to_string(++n);
}

// -- synthetic images ------------------------------------------------------------------------------------

constexpr u64 BASE = 0x180000000;
constexpr u64 TEXT = 0x1000, RDATA = 0x3000, DATA = 0x5000, END = 0x7000;

std::vector<Section> sections() {
  return {{BASE + TEXT, BASE + RDATA, 0x60000020}, {BASE + RDATA, BASE + DATA, 0x40000040}, {BASE + DATA, BASE + END, 0xC0000040}};
}

Bytes le32b(u32 v) { return Bytes(reinterpret_cast<const char*>(&v), 4); }
Bytes le64b(u64 v) { return Bytes(reinterpret_cast<const char*>(&v), 8); }
Bytes unhex(const std::string& h) {
  Bytes out;
  for (size_t i = 0; i + 1 < h.size(); i += 2) out.push_back(char(std::stoi(h.substr(i, 2), nullptr, 16)));
  return out;
}

struct Side {
  Bytes mem = Bytes(END, '\0');
  std::map<u64, u64> cur;
  std::map<u64, std::pair<u64, u32>> pdata;
  std::vector<u64> relocs;
  std::unordered_map<u64, Import> imports;
  explicit Side(u64 shift) { cur = {{TEXT, TEXT + shift}, {RDATA, RDATA + shift}, {DATA, DATA + shift}}; }
  u64 put(u64 sec, const Bytes& data, u64 align = 16) {
    u64 at = (cur[sec] + align - 1) & ~(align - 1);
    mem.replace(at, data.size(), data);
    cur[sec] = at + data.size();
    return BASE + at;
  }
  u64 reserve(u64 sec, u64 n, u64 align = 16) { return put(sec, Bytes(n, sec == TEXT ? '\xcc' : '\0'), align); }
  void write(u64 va, const Bytes& data) { mem.replace(va - BASE, data.size(), data); }
  Image image() const { return Image::from_parts(BASE, mem, sections(), pdata, relocs, imports); }
};

Bytes rip(u64 at, const Bytes& opcode, u64 target, u64 size, const Bytes& tail = "") {
  return opcode + le32b(u32(i32(i64(target) - i64(at + size)))) + tail;
}
Bytes call(u64 at, u64 target) { return "\xe8" + le32b(u32(i32(i64(target) - i64(at + 5)))); }
Bytes lea_rcx(u64 at, u64 t) { return rip(at, "\x48\x8d\x0d", t, 7); }
Bytes mov_eax_g(u64 at, u64 t) { return rip(at, Bytes("\x8b\x05", 2), t, 6); }

u32 unwind_info(Side& s) {
  Bytes body{char(1), 4, 1, 0, 4, 0x42, 0, 0};
  return u32(s.put(RDATA, body, 4) - BASE);
}

// -- results ---------------------------------------------------------------------------------------------

int failures = 0;

void report(const std::string& name, const char* want, const Problems& probs, bool ok, std::string note = "") {
  std::replace(note.begin(), note.end(), '\n', ' ');
  std::set<std::string> cats;
  for (auto& p : probs) cats.insert(p.first);
  std::string got = probs.empty() ? "MATCH" : join(std::vector<std::string>(cats.begin(), cats.end()), ",");
  if (verbose && !probs.empty()) got += "  " + probs[0].second.substr(0, 110);
  failures += !ok;
  std::string padded = name.size() >= 40 ? name : name + std::string(40 - name.size(), ' ');
  std::printf("%s %s want %-12s got %s%s\n", ok ? "ok " : "BAD", padded.c_str(), want ? want : "MATCH", got.c_str(),
              note.empty() ? "" : ("  (" + note + ")").c_str());
}

// a case passes when MATCH is wanted and there are no problems, or the wanted category is among them
bool verdict(const char* want, const Problems& probs) {
  if (!want) return probs.empty();
  for (auto& p : probs) if (p.first == want) return true;
  return false;
}

// -- data-driven cases ------------------------------------------------------------------------------------

Key key_of(const std::string& kind, const Value& v) {
  if (kind == "va") return Key::of_va(u64(v.as_int()));
  static const std::map<std::string, Key::Kind> kinds{{"const", Key::CONST}, {"str", Key::STR}, {"td", Key::TD},
                                                     {"ti", Key::TI}, {"vbt", Key::VBT}, {"unresolved", Key::UNRESOLVED}};
  return Key::named(kinds.at(kind), v.as_str());
}

Image side_image(const Value& s) {
  Bytes mem(END, '\0');
  for (auto& c : s["mem"].arr) {
    Bytes b = unhex(c.arr[1].as_str());
    mem.replace(size_t(c.arr[0].as_int()), b.size(), b);
  }
  std::map<u64, std::pair<u64, u32>> pdata;
  for (auto& p : s["pdata"].arr) pdata[u64(p.arr[0].as_int())] = {u64(p.arr[1].as_int()), u32(p.arr[2].as_int())};
  std::vector<u64> relocs;
  for (auto& r : s["relocs"].arr) relocs.push_back(u64(r.as_int()));
  std::unordered_map<u64, Import> imports;
  for (auto& i : s["imports"].arr)
    imports[u64(i.arr[0].as_int())] = Import{i.arr[1].as_str(), i.arr[2].is_null() ? "" : i.arr[2].as_str(), u32(i.arr[3].as_int())};
  return Image::from_parts(BASE, mem, sections(), pdata, relocs, imports);
}

std::vector<u64> u64s(const Value* v) {
  std::vector<u64> out;
  if (v) for (auto& x : v->arr) out.push_back(u64(x.as_int()));
  return out;
}

// one comparison, the hooks answering from the case's mapping
Problems replay(const Value& c) {
  Image O = side_image(c["orig"]), R = side_image(c["rebuilt"]);
  const Value& m = c["mapping"];
  auto keys = std::make_shared<std::map<u64, Key>>();
  for (auto& k : m["keys"].arr) (*keys)[u64(k.arr[0].as_int())] = key_of(k.arr[1].as_str(), k.arr[2]);
  std::map<u64, std::vector<u64>> vtables;
  for (auto& v : c["vtables"].arr) vtables[u64(v.arr[0].as_int())] = u64s(&v.arr[1]);
  std::unordered_map<u64, std::string> names;
  for (auto& n : c["names"].arr) names[u64(n.arr[0].as_int())] = n.arr[1].as_str();
  auto resolve = [keys](u64 t) {
    auto it = keys->find(t);
    return it != keys->end() ? it->second : Key::named(Key::UNRESOLVED, hex(t));
  };
  Comparer cmp(&O, &R, resolve, vtables, names);
  std::map<u64, std::vector<u64>> folded, refs;
  for (auto& f : m["folded"].arr) folded[u64(f.arr[0].as_int())] = u64s(&f.arr[1]);
  for (auto& f : m["refs"].arr) refs[u64(f.arr[0].as_int())] = u64s(&f.arr[1]);
  std::map<u64, int> folded_locals;
  for (auto& f : m["folded_locals"].arr) folded_locals[u64(f.arr[0].as_int())] = int(f.arr[1].as_int());
  std::map<u64, std::optional<std::vector<u64>>> home;
  for (auto& h : m["home"].arr) home[u64(h.arr[0].as_int())] = h.arr[1].is_null() ? std::nullopt : std::optional(u64s(&h.arr[1]));
  std::map<u64, u64> same_code, orig_ends;
  for (auto& s : m["same_code"].arr) same_code[u64(s.arr[0].as_int())] = u64(s.arr[1].as_int());
  if (auto* e = m.get("orig_ends")) for (auto& x : e->arr) orig_ends[u64(x.arr[0].as_int())] = u64(x.arr[1].as_int());
  std::vector<std::pair<u64, u64>> padding;
  if (auto* p = m.get("padding")) for (auto& x : p->arr) padding.emplace_back(u64(x.arr[0].as_int()), u64(x.arr[1].as_int()));
  auto local = u64s(m.get("local")), literals = u64s(m.get("literals")), starts = u64s(m.get("starts")),
       named = u64s(m.get("named")), annotated = u64s(m.get("annotated"));
  std::sort(starts.begin(), starts.end());

  cmp.alternates = [folded](u64 t) { auto it = folded.find(t); return it == folded.end() ? std::vector<u64>() : it->second; };
  cmp.local_base = [local](u64 t) -> std::optional<std::pair<u64, u64>> {
    for (u64 s : local) if (s <= t && t < s + 16) return std::make_pair(s, t - s);
    return std::nullopt;
  };
  cmp.folded_locals = [folded_locals](u64 t) { auto it = folded_locals.find(t); return it == folded_locals.end() ? 1 : it->second; };
  cmp.static_home = [home](u64 t) -> std::optional<std::vector<u64>> {
    auto it = home.find(t);
    return it == home.end() ? std::nullopt : it->second;
  };
  cmp.orig_object_end = [orig_ends](u64 t) { auto it = orig_ends.find(t); return it == orig_ends.end() ? t : it->second; };
  cmp.orig_padding = [padding](u64 t) {
    for (auto& [lo, hi] : padding) if (lo <= t && t < hi) return true;
    return false;
  };
  cmp.orig_refs = [refs](u64 f) { auto it = refs.find(f); return it == refs.end() ? std::vector<u64>() : it->second; };
  cmp.infer = [same_code](u64 o_t, u64 r_t) { auto it = same_code.find(r_t); return it != same_code.end() && it->second == o_t; };
  const Image* Rp = &R;
  cmp.literal_at = [literals, keys, Rp](u64 t) -> std::optional<std::pair<u64, Key>> {
    for (u64 v : literals) {
      Key k = keys->at(v);
      if (v <= t && i64(t - v) < literal_size(*Rp, v, k)) return std::make_pair(v, k);
    }
    return std::nullopt;
  };
  cmp.symbol_start = [starts](u64 t) { return std::binary_search(starts.begin(), starts.end(), t); };
  if (!starts.empty()) {
    cmp.span = [starts](u64 t) -> u64 {
      for (u64 s : starts) if (s > t) return s - t;
      return 0x100;
    };
    cmp.containing = [starts](u64 t) -> std::optional<u64> {
      std::optional<u64> best;
      for (u64 s : starts) if (s <= t) best = s;
      return best;
    };
  }
  cmp.orig_named = [named](u64 t) { return std::find(named.begin(), named.end(), t) != named.end(); };
  cmp.annotated_between = [annotated](u64 lo, u64 hi) {
    for (u64 a : annotated) if (lo < a && a <= hi) return true;
    return false;
  };
  if (auto* pb = m.get("pre_bound")) {
    u64 rb = u64(pb->arr[0].as_int()), ob = u64(pb->arr[1].as_int());
    cmp.bound.set(rb, ob);
    cmp.bound_o.set(ob, rb);
  }
  cmp.end_of_previous = [starts, keys](u64 t) -> std::optional<u64> {
    if (!std::binary_search(starts.begin(), starts.end(), t)) return std::nullopt;
    for (auto it = starts.rbegin(); it != starts.rend(); ++it) {
      u64 p = *it;
      auto k = keys->find(p);
      if (p < t && k != keys->end() && k->second.kind == Key::VA) return k->second.va + t - p;
    }
    return std::nullopt;
  };
  u64 o0 = u64(c["ofn"].arr[0].as_int()), o1 = u64(c["ofn"].arr[1].as_int());
  u64 r0 = u64(c["rfn"].arr[0].as_int()), r1 = u64(c["rfn"].arr[1].as_int());
  auto oe = O.extent(o0), re = R.extent(r0);
  return cmp.function(o0, oe && *oe ? *oe : o1, r0, re && *re ? *re : r1);
}

void data_cases(const Value& doc) {
  for (auto& c : doc["cases"].arr) {
    std::string name = c["name"].as_str();
    std::string want_s = c["want"].is_null() ? "" : c["want"].as_str();
    const char* want = want_s.empty() ? nullptr : want_s.c_str();
    Problems probs, expected;
    for (auto& p : c["problems"].arr) expected.push_back({p.arr[0].as_str(), p.arr[1].as_str()});
    std::string note;
    bool ok;
    try {
      probs = replay(c);
      ok = verdict(want, probs) && probs == expected;
      if (probs != expected) {
        note = "expected: ";
        for (auto& [a, b] : expected) note += a + ": " + b + "; ";
        if (expected.empty()) note += "MATCH";
      }
    } catch (std::exception& e) {
      ok = false;
      note = std::string("ERROR ") + e.what();
    }
    report(name, want, probs, ok, note);
  }
}

// -- cases in code ----------------------------------------------------------------------------------------

Problems bad_if(bool bad, const std::string& cat, const std::string& why) { return bad ? Problems{{cat, why}} : Problems{}; }

Op opm(const char* base, i64 disp, int size) {
  Op o{};
  o.k = Op::M; o.base = base; o.scale = 1; o.v = disp; o.size = size;
  return o;
}
Op opi(i64 v) { Op o{}; o.k = Op::I; o.v = v; return o; }
Op opsym(Key k) { Op o{}; o.k = Op::SYM; o.key = std::move(k); return o; }
Op opr(const char* r) { Op o{}; o.k = Op::R; o.base = r; return o; }
Op oprel(i64 v) { Op o{}; o.k = Op::REL; o.v = v; return o; }

Problems category(i64 rimm, u64 rtarget, bool branch) {
  Toks a, b;
  if (branch) {
    a = {{"cmp", {opm("rcx", 0x48, 1), opi(0)}}, {"jne", {opsym(Key::of_va(0x180001a00))}}};
    b = {{"cmp", {opm("rcx", 0x48, 1), opi(0)}}, {"jne", {opsym(Key::of_va(rtarget))}}};
  } else {
    a = {{"cmp", {opm("rcx", 0x48, 1), opi(0)}}};
    b = {{"cmp", {opm("rcx", 0x48, 1), opi(rimm)}}};
  }
  return {{classify(a, b), ""}};
}

Problems build_hashes() {
  Comparer c(nullptr, nullptr, [](u64) { return Key::named(Key::UNRESOLVED, ""); });
  Bytes a = ".?AVX@?A0x11111111@@", b = ".?AVX@?A0x22222222@@";
  auto rtti_of = [](const Bytes& name, u32 off) { Rtti r; r.present = true; r.name = name; r.off = off; return r; };
  Problems bad;
  if (!c.same_names({{a, b}}) || !c.same_rtti(rtti_of(a, 1), rtti_of(b, 1)))
    bad.push_back({"hash", "same name, other hash"});
  if (c.same_names({{a, ".?AVX@?A0x33333333@@"}}) || c.same_names({{".?AVX@?A0x44444444@@", b}}))
    bad.push_back({"hash", "a hash paired twice"});
  if (c.same_rtti(rtti_of(a, 1), rtti_of(b, 2)) || c.same_names({{".?AVY@?A0x55555555@@", ".?AVZ@?A0x66666666@@"}}))
    bad.push_back({"hash", "other value or name"});
  if (c.same_rtti(rtti_of(".?AVW@?A0x99999999@@", 1), rtti_of(".?AVW@?A0xaaaaaaaa@@", 2)) ||
      !c.same_names({{".?AVW@?A0x99999999@@", ".?AVW@?A0xbbbbbbbb@@"}}))
    bad.push_back({"hash", "a failed comparison left a pairing behind"});
  return bad;
}

Problems qualified_names() {
  std::vector<std::pair<std::string, std::string>> cases = {
      {"public: virtual void * __cdecl A::B::`scalar deleting destructor'(unsigned int)", "A::B::`scalar deleting destructor'"},
      {"[thunk]:public: virtual void * __cdecl A::B::`scalar deleting destructor'`adjustor{8}' (unsigned int)",
       "A::B::`scalar deleting destructor'`adjustor{8}'"},
      {"[thunk]:public: virtual void * __cdecl A::C::`vector deleting destructor'`adjustor{8}' (unsigned int)",
       "A::C::`vector deleting destructor'`adjustor{8}'"},
      {"public: int __cdecl A::B::Get(void)const ", "A::B::Get"},
      {"public: void __cdecl N::Vector<struct N::Id const * __ptr64>::PushBack(struct N::Id const * __ptr64 const & __ptr64,bool) __ptr64",
       "N::Vector<N::Id const*>::PushBack"},
      {"public: virtual void * __ptr64 __cdecl N::Vector<struct N::Id const * __ptr64>::`scalar deleting destructor'(unsigned int) __ptr64",
       "N::Vector<N::Id const*>::`scalar deleting destructor'"},
      {"public: bool __cdecl N::S::operator<(class N::S const & __ptr64)const __ptr64", "N::S::operator<"},
      {"public: bool __cdecl N::S::operator>(class N::S const & __ptr64)const __ptr64", "N::S::operator>"},
      {"public: int __cdecl N::F::operator()(int) __ptr64", "N::F::operator()"},
      {"void __cdecl operator delete(void * __ptr64)", "operator delete"},
      {"void * __ptr64 __cdecl operator new[](unsigned __int64)", "operator new[]"},
      {"public: __cdecl N::S::operator bool(void)const __ptr64", "N::S::operator bool"},
      {"void __cdecl `dynamic atexit destructor for 'g_x''(void)", "`dynamic atexit destructor for 'g_x''"},
      {"void __cdecl `dynamic initializer for 'N::g_x''(void)", "`dynamic initializer for 'N::g_x''"},
      {"void __cdecl `struct S const * __ptr64 __cdecl N::f(int)'::`2'::`dynamic atexit destructor for 's_x''(void)",
       "N::f::`dynamic atexit destructor for 's_x''"},
      {"[thunk]:public: virtual void * __ptr64 __cdecl N::A::`vector deleting destructor'`vtordisp{4294967292,0}' (unsigned int) __ptr64",
       "N::A::`vector deleting destructor'`vtordisp{4294967292,0}'"},
      {"public: void __cdecl N::E<class N::I * __ptr64>::`vbase destructor'(void) __ptr64", "N::E<N::I*>::`vbase destructor'"},
      {"public: void __cdecl `anonymous namespace'::S::f(int) __ptr64", "`anonymous namespace'::S::f"},
      {"int (__cdecl*__cdecl select_printer(struct box * __ptr64))(struct _iobuf * __ptr64,int)", "select_printer"},
  };
  Problems bad;
  for (auto& [u, want] : cases) if (qualified(u) != want) bad.push_back({"name", u + " -> " + qualified(u)});
  std::vector<std::pair<std::string, std::string>> owners = {
      {"int `int __cdecl N::f(void)'::`2'::x", "N::f"},
      {"unsigned __int64 `__local_stdio_printf_options'::`2'::_OptionsStorage", "__local_stdio_printf_options"},
  };
  for (auto& [u, want] : owners) if (static_owner(u) != want) bad.push_back({"static owner", u + " -> " + static_owner(u)});
  std::vector<std::pair<std::string, std::string>> sigs = {
      {"void __cdecl operator delete(void * __ptr64)", "(void*)"},
      {"void __cdecl operator delete(void * __ptr64,unsigned __int64)", "(void*,unsigned __int64)"},
      {"public: __cdecl N::S::S(class N::S const & __ptr64) __ptr64", "(S const&)"},
      {"public: int __cdecl A::B::Get(void)const ", "(void)"},
      {"public: bool __cdecl N::S::operator<(class N::S const & __ptr64)const __ptr64", "(S const&)"},
      {"int (__cdecl*__cdecl select_printer(struct box * __ptr64))(struct _iobuf * __ptr64,int)", "(box*)"},
      {"void __cdecl f(void (__cdecl*)(int))", "(void (__cdecl*)(int))"},
  };
  for (auto& [u, want] : sigs) if (signature(u) != want) bad.push_back({"signature", u + " -> " + signature(u)});
  if (norm_params("(char const *)") != norm_params("(char const*)") || norm_params("()") != "(void)")
    bad.push_back({"signature", "norm_params spelling"});
  return bad;
}

Problems definition_names() {
  std::vector<std::pair<std::string, std::optional<std::string>>> cases = {
      {"String& String::operator=(const Char* c)", "String::operator="},
      {"Value& Value::operator[](Int32 index)", "Value::operator[]"},
      {"bool S::operator<(const S& o) const", "S::operator<"},
      {"__declspec(noinline) void N::S::Clear()", "N::S::Clear"},
      {"Gfx::Color N::Model::GetColor(int i) const", "N::Model::GetColor"},
      {"extern \"C\" void* __fastcall sub_180001000(void*, unsigned int)", "sub_180001000"},
      {"const Vector<Value*>* Foo::Bar()", "Foo::Bar"},
      {"    virtual ~Exc() throw() {}", "~Exc"},
      {"// FUNCTION: EXAMPLE 0x180001000 (int)", std::nullopt},
      {"{", std::nullopt},
  };
  Problems bad;
  for (auto& [line, want] : cases)
    if (definition_name(line) != want) bad.push_back({"name", line + " -> " + definition_name(line).value_or("None")});
  return bad;
}

Problems destructor_pairing() {
  std::string dd = "N::X::`scalar deleting destructor'";
  auto both = [](const std::string&) { return true; };
  std::function<bool(const std::string&)> only_dd = [&](const std::string& n) { return n == dd; };
  std::function<bool(const std::string&)> no_dd = [&](const std::string& n) { return n != dd; };
  struct C { bool in_slot; std::function<bool(const std::string&)> has; std::string want; };
  std::vector<C> cases = {{true, both, dd}, {false, both, "N::X::~X"}, {false, only_dd, dd}, {true, no_dd, "N::X::~X"}};
  Problems bad;
  for (auto& c : cases) {
    auto got = pick_destructor("N::X::~X", c.in_slot, c.has);
    if (got != c.want) bad.push_back({"name", got});
  }
  return bad;
}

Lookup fixed_lookup(const std::map<std::string, u64>& m, const std::string& key) { return {{m.at(key)}, key, 1}; }

// a Rebuilt whose tables a test fills, answering what the test sets in `fake` (the real code for the rest)
struct FakeRebuilt : Rebuilt {
  struct {
    std::function<Lookup(const std::string&, const std::optional<std::string>&, bool)> lookup;
    std::function<u64(u64)> extent, span;
    std::function<std::optional<std::pair<u64, u64>>(u64)> local_base;
    std::function<std::string(std::string_view)> qualified;
  } fake;
  std::string qualified(std::string_view d) const override { return fake.qualified ? fake.qualified(d) : Rebuilt::qualified(d); }
  Lookup lookup(const std::string& k, const std::optional<std::string>& sig, bool code) const override {
    return fake.lookup ? fake.lookup(k, sig, code) : Rebuilt::lookup(k, sig, code);
  }
  u64 extent(u64 va) const override { return fake.extent ? fake.extent(va) : Rebuilt::extent(va); }
  u64 span(u64 t) const override { return fake.span ? fake.span(t) : Rebuilt::span(t); }
  std::optional<std::pair<u64, u64>> local_base(u64 t) const override {
    return fake.local_base ? fake.local_base(t) : Rebuilt::local_base(t);
  }
};

Problems folded_annotations() {
  Original orig;
  FakeRebuilt reb;
  reb.by_va = {{0x100, {"?A@@YAXXZ", "?B@@YAXXZ"}}, {0x200, {"?C@@YAXXZ"}}};
  reb.by_va_order = reb.sym_vas = {0x100, 0x200};
  reb.fake.qualified = [](std::string_view n) { return std::string(n.substr(1, 1)); };
  std::map<std::string, u64> m{{"A", 0x100}, {"B", 0x100}, {"C", 0x200}};
  reb.fake.lookup = [m](const std::string& k, auto&, bool) { return fixed_lookup(m, k); };
  std::vector<Annotation> anns = {{"FUNCTION", 0x1000, "A", {}, "a.cpp", 1}, {"FUNCTION", 0x2000, "B", {}, "b.cpp", 1},
                                  {"FUNCTION", 0x3000, "C", {}, "c.cpp", 1}};
  Pairing p(orig, reb, anns);
  auto a1 = p.alternates(0x100), a2 = p.alternates(0x200);
  bool ok = std::set<u64>(a1.begin(), a1.end()) == std::set<u64>{0x1000, 0x2000} && a2.empty();
  return bad_if(!ok, "alternates", "wrong alternates");
}

Problems instruction_diff() {
  auto insns = [](std::vector<u64> as) {
    std::vector<Insn> v;
    for (u64 a : as) { Insn i; i.address = a; v.push_back(i); }
    return v;
  };
  Toks o_toks = {{"push", {opr("rbx")}}, {"je", {oprel(7)}}, {"call", {opsym(Key::of_va(0x180001000))}}, {"pop", {opr("rbx")}}};
  Toks r_toks = {{"push", {opr("rbx")}}, {"je", {oprel(10)}}, {"nop", {}}, {"call", {opsym(Key::named(Key::UNRESOLVED, "Foo"))}},
                 {"pop", {opr("rbx")}}};
  auto oi = insns({0, 1, 3, 7}), ri = insns({0, 1, 3, 4, 10});
  std::unordered_map<u64, std::string> names{{0x180001000, "Bar"}};
  Problems bad;
  auto got = insn_diff(oi, ri, o_toks, r_toks, names, 1);
  std::vector<std::string> want = {"@1", "  je <+0x7>", "- call Bar", "+ nop", "+ call Foo", "  pop rbx"};
  if (got != want) bad.push_back({"diff", join(got, " | ")});
  r_toks[1] = {"je", {oprel(0)}};
  got = insn_diff(oi, ri, o_toks, r_toks, names, 0);
  want = {"@1", "- je <+0x7>", "+ je <+0x0>", "- call Bar", "+ nop", "+ call Foo"};
  if (got != want) bad.push_back({"diff", join(got, " | ")});
  return bad;
}

Problems linear_matcher(const Value& doc) {
  for (auto& c : doc["matcher"].arr) {
    std::vector<int> a, b;
    for (auto& x : c["a"].arr) a.push_back(int(x.as_int()));
    for (auto& x : c["b"].arr) b.push_back(int(x.as_int()));
    auto& r = c["r"].arr;
    auto m = find_longest_match(a, b, size_t(r[0].as_int()), size_t(r[1].as_int()), size_t(r[2].as_int()), size_t(r[3].as_int()));
    auto& w = c["match"].arr;
    bool ok = m.i == size_t(w[0].as_int()) && m.j == size_t(w[1].as_int()) && m.k == size_t(w[2].as_int());
    auto ops = get_opcodes(a, b);
    auto& wo = c["opcodes"].arr;
    ok = ok && ops.size() == wo.size();
    for (size_t i = 0; ok && i < ops.size(); ++i) {
      auto& x = wo[i].arr;
      ok = ops[i].tag == x[0].as_str()[0] && ops[i].i1 == size_t(x[1].as_int()) && ops[i].i2 == size_t(x[2].as_int()) &&
           ops[i].j1 == size_t(x[3].as_int()) && ops[i].j2 == size_t(x[4].as_int());
    }
    if (!ok) return {{"matcher", json::dump(c).substr(0, 200)}};
  }
  return {};
}

Problems leaf_extent_case() {
  std::string mov = unhex("b801000000");
  auto times = [](const std::string& s, int n) { std::string r; for (int i = 0; i < n; ++i) r += s; return r; };
  std::vector<std::pair<std::string, std::optional<u64>>> cases = {
      {times(mov, 20) + unhex("c3"), TEXT + 101},
      {unhex("7466") + times(mov, 20) + unhex("c390c3"), TEXT + 105},
      {times(mov, 14) + unhex("06c3"), std::nullopt},
  };
  Problems bad;
  for (auto& [code, want] : cases) {
    Bytes mem(END, '\0');
    mem.replace(TEXT, code.size(), code);
    Image img = Image::from_parts(BASE, mem, sections(), {}, {}, {});
    auto got = leaf_extent(img, BASE + TEXT);
    std::optional<u64> w = want ? std::optional<u64>(BASE + *want) : std::nullopt;
    if (got != w) bad.push_back({"leaf extent", hex_bytes(code).substr(0, 24) + ": " + (got ? hex(*got) : "None")});
  }
  return bad;
}

// the same code decoded at two addresses (relative branches, RIP-relative operands): capstone's text and sizes
Problems decode_case(const Value& doc) {
  Problems bad;
  for (auto& d : doc["decode"].arr) {
    Bytes code = unhex(d["code"].as_str());
    u64 address = u64(d["address"].as_int());
    auto insns = decode_linear(code, address);
    auto& want = d["insns"].arr;
    bool ok = insns.size() == want.size();
    for (size_t i = 0; ok && i < insns.size(); ++i) {
      auto& w = want[i].arr;
      ok = insns[i].address == u64(w[0].as_int()) && insns[i].size == w[1].as_int() && insns[i].mnemonic == w[2].as_str() &&
           insns[i].op_str() == w[3].as_str();
    }
    if (!ok) bad.push_back({"decode memo", "at " + hex(address)});
  }
  return bad;
}

Problems local_static_names() {
  std::vector<std::pair<std::string, bool>> cases = {
      {"?$S3@?1??GetSharedMutex@@YAPEAVmutex@std@@XZ@4IA", true},
      {"?unpacked@?1??unpack_language@@YAPEADG@Z@4PADA", true},
      {"?table@?BA@??read_record@@YAHPEAUrecord@@PEAX@Z@4QBU<unnamed-type-table>"
       "@?BA@??1@YAH01@Z@B", true},
      {"?g_foo@@3HA", false},
      {"?x@Cls@@2HA", false},
      {"?x@?A0x12345678@ns@@3HA", false},
  };
  Problems bad;
  for (auto& [n, want] : cases) if ((local_static_match(n) != 0) != want) bad.push_back({"local static", n});
  return bad;
}

Problems stub_pairing() {
  Original orig;
  FakeRebuilt reb;
  reb.by_va = {{0x100, {"sub_1000"}}, {0x200, {"A"}}};
  reb.by_va_order = reb.sym_vas = {0x100, 0x200};
  std::map<std::string, u64> m{{"sub_1000", 0x100}, {"A", 0x200}};
  reb.fake.lookup = [m](const std::string& k, auto&, bool) { return fixed_lookup(m, k); };
  Pairing p(orig, reb, {{"STUB", 0x1000, "sub_1000", {}, "s.cpp", 1}, {"FUNCTION", 0x2000, "A", {}, "a.cpp", 1}});
  bool ok = !p.paired_o.count(0x1000) && p.paired_o.count(0x2000);
  return bad_if(!ok, "paired", "stub/function paired wrongly");
}

Problems global_bytes() {
  Side o(0), r(0x240);
  u64 oa = o.put(RDATA, Bytes("STANDARD\0", 9)), ob = o.put(RDATA, Bytes("EXPANDED\0", 9)), ow = o.put(DATA, Bytes("\1\0\0\0", 4));
  u64 ra = r.put(RDATA, Bytes("STANDARD\0", 9)), rb = r.put(RDATA, Bytes("EXPANDED\0", 9)), rw = r.put(DATA, Bytes("\2\0\0\0", 4));
  Image O = o.image(), R = r.image();
  std::map<std::string, u64> names{{"g_std", ra}, {"g_exp", rb}, {"g_w", rw}};
  std::vector<Annotation> anns = {{"GLOBAL", oa, "g_std", {}, "a.cpp", 1}, {"GLOBAL", oa, "g_exp", {}, "a.cpp", 2},
                                  {"GLOBAL", ow, "g_w", {}, "a.cpp", 3}, {"GLOBAL", ob, "g_gone", {}, "a.cpp", 4},
                                  {"FUNCTION", ob, "g_std", {}, "a.cpp", 5}};
  std::unordered_map<u64, u64> reb_to_orig{{ra, oa}, {rb, oa}, {rw, ow}};
  Comparer c(&O, &R, [&](u64 t) {
    auto it = reb_to_orig.find(t);
    return it != reb_to_orig.end() ? Key::of_va(it->second) : Key::named(Key::UNRESOLVED, "");
  });
  c.span = [](u64) { return u64(16); };
  auto lookup = [&](const std::string& n) { auto it = names.find(n); return it == names.end() ? std::vector<u64>() : std::vector<u64>{it->second}; };
  std::vector<std::string> got;
  for (auto& g : check_globals(anns, lookup, reb_to_orig, c)) got.push_back(g.ann->name);
  return bad_if(got != std::vector<std::string>{"g_exp"}, "globals", "reported " + join(got, ","));
}

Problems replay_key() {
  namespace fs = std::filesystem;
  fs::path d = fs::temp_directory_path() / ("verifier-test-" + unique_suffix());
  fs::create_directories(d / "src");
  Problems bad;
  std::map<std::string, std::string> files{{"x.dll", (d / "x.dll").string()}, {"x.map", (d / "x.map").string()},
                                           {"matched.txt", (d / "matched.txt").string()}, {"src/a.cpp", (d / "src" / "a.cpp").string()}};
  Args a;
  a.rebuilt = files["x.dll"];
  a.map = files["x.map"];
  a.matched = files["matched.txt"];
  a.has_matched = true;
  a.src = {(d / "src").string()};
  Config p;
  std::vector<std::string> args;
  auto write = [](const std::string& path, const std::string& text) { std::ofstream(path, std::ios::binary) << text; };
  std::vector<std::pair<std::string, std::function<void()>>> changes;
  for (auto& [n, path] : files) changes.emplace_back(n, [&write, path = path] { write(path, "2"); });
  changes.emplace_back("added source", [&] { write((d / "src" / "b.h").string(), ""); });
  changes.emplace_back("arguments", [&] { args.push_back("--json"); });
  for (auto& [name, change] : changes) {
    for (auto& [n, path] : files) write(path, "1");
    args = {"--check"};
    std::error_code ec;
    fs::remove(d / "src" / "b.h", ec);
    std::string key = run_key(args, a, p, "verifier");
    if (run_key(args, a, p, "verifier") != key) bad.push_back({"replay", "the key of the same inputs differs"});
    change();
    if (run_key(args, a, p, "verifier") == key) bad.push_back({"replay", "the key ignores " + name});
  }
  if (run_key(args, a, p, "verifier") == run_key(args, a, p, "another verifier")) bad.push_back({"replay", "the key ignores the verifier"});
  std::error_code ec;
  fs::remove_all(d, ec);
  return bad;
}

Problems failed_inference() {
  Side o(0), r(0x240);
  struct Fns { u64 A, X, G, F; } fo{}, fr{};
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
  for (auto [va, size] : {std::pair<u64, u64>{fo.A, 13}, {fo.G, 6}, {fo.F, 8}}) orig.functions[va] = IdaFunction{va, size, "", false, false};
  FakeRebuilt reb;
  reb.sym_vas = {fr.A, fr.G, fr.F, fr.X};
  std::sort(reb.sym_vas.begin(), reb.sym_vas.end());
  for (u64 v : reb.sym_vas) reb.by_va[v] = {};
  std::map<u64, u64> rsize{{fr.A, 13}, {fr.G, 6}, {fr.F, 8}};
  reb.fake.extent = [rsize](u64 va) { return va + rsize.at(va); };
  std::map<std::string, u64> m{{"X", fr.X}, {"G", fr.G}, {"F", fr.F}};
  reb.fake.lookup = [m](const std::string& k, auto&, bool) { return fixed_lookup(m, k); };
  Pairing p(orig, reb, {{"GLOBAL", fo.X, "X", {}, "x.cpp", 1}, {"FUNCTION", fo.G, "G", {}, "g.cpp", 1}, {"FUNCTION", fo.F, "F", {}, "f.cpp", 1}});
  Image O = o.image(), R = r.image();
  p.use(std::make_unique<Comparer>(&O, &R, [&p](u64 t) { return p.resolve_symbol(t); }));
  p.cmp->infer = [&p](u64 a, u64 b) { return p.infer(a, b); };
  auto g = p.cmp->function(fo.G, fo.G + 6, fr.G, fr.G + 6);
  auto f = p.cmp->function(fo.F, fo.F + 8, fr.F, fr.F + 8);
  return g.empty() ? Problems{{"setup", "G should differ"}} : f;
}

// a Pairing over fake Original/Rebuilt with real hooks (prebound_static, consensus_static, folded_original)
struct FakeRun {
  Image O, R;
  Original orig;
  FakeRebuilt reb;
  std::unique_ptr<Pairing> p;
  std::unique_ptr<CodeCache> oc, rc;
  Comparer* c = nullptr;
  void start(const std::vector<Annotation>& anns) {
    orig.img = O;
    reb.img = R;
    p = std::make_unique<Pairing>(orig, reb, anns);
    oc = std::make_unique<CodeCache>(&orig.img);
    rc = std::make_unique<CodeCache>(&reb.img);
    c = &p->comparer(*oc, *rc);
  }
};

Problems prebound_static(bool owner_first) {
  Side o(0), r(0x240);
  struct S { u64 sf, sg, F, G; } so{}, sr{};
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
  for (u64 va : {so.F, so.G}) run.orig.functions[va] = IdaFunction{va, 7, "", false, false};
  auto& reb = run.reb;
  reb.sym_vas = {sr.F, sr.G, sr.sf, sr.sg};
  std::sort(reb.sym_vas.begin(), reb.sym_vas.end());
  for (u64 v : reb.sym_vas) { reb.by_va[v] = {}; reb.by_va_order.push_back(v); }
  reb.local_statics = {sr.sf, sr.sg};
  reb.static_owner = {{sr.sf, std::set<u64>{sr.F}}, {sr.sg, std::set<u64>{sr.G}}};
  reb.fake.extent = [](u64 va) { return va + 7; };
  std::map<std::string, u64> m{{"F", sr.F}, {"G", sr.G}};
  reb.fake.lookup = [m](const std::string& k, auto&, bool) { return fixed_lookup(m, k); };
  reb.fake.local_base = [sr](u64 t) -> std::optional<std::pair<u64, u64>> {
    for (u64 b : {sr.sf, sr.sg}) if (b <= t && t < b + 4) return std::make_pair(b, t - b);
    return std::nullopt;
  };
  reb.fake.span = [](u64) { return u64(16); };
  run.start({{"FUNCTION", so.F, "F", {}, "f.cpp", 1}, {"FUNCTION", so.G, "G", {}, "g.cpp", 1}});
  std::vector<std::pair<u64, u64>> order;
  if (owner_first) order.emplace_back(so.G, sr.G);
  order.emplace_back(so.F, sr.F);
  Problems probs;
  for (auto [of, rf] : order) probs = run.c->function(of, of + 7, rf, rf + 7);
  return probs;
}

Problems consensus_static() {
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
  for (auto& [n, f] : fns) {
    run.orig.functions[f.first] = IdaFunction{f.first, 7, "", false, false};
    reb.sym_vas.push_back(f.second);
    m[n] = f.second;
    anns.push_back({"FUNCTION", f.first, n, {}, n + ".cpp", 1});
  }
  reb.sym_vas.push_back(rs);
  std::sort(reb.sym_vas.begin(), reb.sym_vas.end());
  for (u64 v : reb.sym_vas) { reb.by_va[v] = {}; reb.by_va_order.push_back(v); }
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

Problems folded_original(bool same_code) {
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
  run.orig.functions[oo] = IdaFunction{oo, 4, "", false, false};
  run.orig.functions[oG] = IdaFunction{oG, 6, "", false, false};
  auto& reb = run.reb;
  reb.sym_vas = {ra, rb, rG};
  std::sort(reb.sym_vas.begin(), reb.sym_vas.end());
  for (u64 v : reb.sym_vas) { reb.by_va[v] = {}; reb.by_va_order.push_back(v); }
  reb.fake.extent = [rG](u64 va) { return va + (va == rG ? 6 : 4); };
  std::map<std::string, u64> m{{"A", ra}, {"G", rG}};
  reb.fake.lookup = [m](const std::string& k, auto&, bool) { return fixed_lookup(m, k); };
  reb.fake.local_base = [](u64) { return std::optional<std::pair<u64, u64>>(); };
  reb.fake.span = [](u64) { return u64(16); };
  run.start({{"FUNCTION", oo, "A", {}, "a.cpp", 1}, {"FUNCTION", oG, "G", {}, "g.cpp", 1}});
  return run.c->function(oG, oG + 6, rG, rG + 6);
}

Problems addend_across_annotation(u64 off) {
  Side o(0), r(0x240);
  u64 og = o.put(DATA, Bytes(0x20, '\0'), 16), oy = o.put(DATA, Bytes(4, '\0'), 16);
  u64 rg = r.put(DATA, Bytes(0x40, '\0'), 16), ry = r.put(DATA, Bytes(4, '\0'), 16);
  Original orig;
  FakeRebuilt reb;
  reb.sym_vas = {rg, ry};
  reb.by_va = {{rg, {"?g@@3HA"}}, {ry, {"?y@@3HA"}}};
  reb.by_va_order = {rg, ry};
  reb.fake.qualified = [](std::string_view n) { return std::string(n.substr(1, 1)); };
  std::map<std::string, u64> m{{"g", rg}, {"y", ry}};
  reb.fake.lookup = [m](const std::string& k, auto&, bool) { return fixed_lookup(m, k); };
  reb.fake.local_base = [](u64) { return std::optional<std::pair<u64, u64>>(); };
  Pairing p(orig, reb, {{"GLOBAL", og, "g", {}, "g.cpp", 1}, {"GLOBAL", oy, "y", {}, "y.cpp", 1}});
  p.use(std::make_unique<Comparer>(nullptr, nullptr, [&p](u64 t) { return p.resolve(t); }));
  Key got = p.resolve(rg + off);
  return bad_if(!got.is_va(og + off), "reference", "g+" + hex(off) + " resolves to " + got.text());
}

Problems ignored_annotations() {
  namespace fs = std::filesystem;
  fs::path d = fs::temp_directory_path() / ("verifier-ann-" + unique_suffix());
  fs::create_directories(d);
  std::map<std::string, std::string> src{
      {"a.cpp", "// STUB: EXAMPLE 0x180001000\n"},
      {"b.cpp", "// STUB: EXAMPLE 0x180002000\nextern \"C\" void* unk_180002000 = nullptr;\n"},
      {"c.cpp", "// FUNCTION: EXAMPLE 0x180003000\n// a\n// b\n// c\nvoid f(int) {}\n"},
      {"d.cpp", "// FUNCTION: EXAMPLE 0x180004000\nvoid g(int) {}\n// GLOBAL: EXAMPLE 0x180005000\nint h = 1;\n"}};
  for (auto& [n, text] : src) std::ofstream(d / n, std::ios::binary) << text;
  std::vector<Ignored> ignored;
  auto anns = parse_annotations({d.string()}, "EXAMPLE", &ignored);
  std::error_code ec;
  fs::remove_all(d, ec);
  std::vector<std::pair<std::string, int>> got;
  for (auto& i : ignored) got.emplace_back(basename(i.path), i.line);
  std::sort(got.begin(), got.end());
  Problems bad;
  if (got != std::vector<std::pair<std::string, int>>{{"a.cpp", 1}, {"b.cpp", 1}, {"c.cpp", 1}}) bad.push_back({"ignored", "wrong set"});
  if (anns.size() != 2) bad.push_back({"parsed", std::to_string(anns.size()) + " annotations, want 2"});
  return bad;
}

Problems malformed_unwind() {
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
  c.unwind_info(R.pdata.at(fr + 8).second, R.pdata.at(fr + 8).second, fo, fo + 13, fr, fr + 13, 0);
  return bad_if(!(end && *end == fr + 8), "extent", end ? hex(*end) : "None");
}

// unit check: the SHA-256 paths agree (SHA instructions where the CPU has them, portable code), and known digests
Problems sha256_paths() {
  Problems bad;
  if (sha256_hex("abc") != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") bad.push_back({"sha256", "abc"});
  if (sha256_hex("") != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") bad.push_back({"sha256", "empty"});
  Bytes data;
  for (int i = 0; i < 5000; ++i) data.push_back(char((i * 131 + 7) ^ (i >> 3)));
  for (size_t n : {0, 1, 55, 56, 63, 64, 65, 127, 128, 129, 1000, 4096, 5000}) {
    Sha256::force_scalar = true;
    std::string a = sha256_hex(std::string_view(data).substr(0, n));
    Sha256::force_scalar = false;
    std::string b = sha256_hex(std::string_view(data).substr(0, n));
    if (a != b) bad.push_back({"sha256", "length " + std::to_string(n)});
  }
  return bad;
}

// unit check: line splitting (\n, \r\n, \r), in memory and streamed in blocks
Problems line_splitting() {
  Problems bad;
  std::string text = "a\nbb\r\nccc\rdddd\n\neee";
  std::vector<std::string> want = {"a", "bb", "ccc", "dddd", "", "eee"}, got;
  for_each_line(text, [&](std::string_view l) { got.emplace_back(l); });
  if (got != want) bad.push_back({"lines", join(got, "|")});
  // streamed: lines across the 1 MB block boundary, a "\r\n" split by it
  namespace fs = std::filesystem;
  fs::path f = fs::temp_directory_path() / ("verifier-lines-" + unique_suffix());
  std::string big;
  std::vector<std::string> want2;
  for (int i = 0; big.size() < (3u << 20); ++i) {
    std::string l(size_t(i * 37 % 1500), char('a' + i % 26));
    want2.push_back(l);
    big += l;
    big += (i % 3 == 0) ? "\r\n" : (i % 3 == 1 ? "\n" : "\r");
  }
  std::ofstream(f, std::ios::binary) << big;
  std::vector<std::string> got2;
  for_each_file_line(f.string(), [&](std::string_view l) { got2.emplace_back(l); });
  std::vector<std::string> got3;
  for_each_line(big, [&](std::string_view l) { got3.emplace_back(l); });
  std::error_code ec;
  fs::remove(f, ec);
  if (got2 != want2 || got3 != want2) bad.push_back({"lines", "streamed " + std::to_string(got2.size()) + " vs " + std::to_string(want2.size())});
  return bad;
}

}  // namespace

int main(int argc, char** argv) {
  std::string path = VERIFIER_FIXTURES;
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "-v") verbose = true;
    else path = a;
  }
  Value doc = json::parse(read_file(path));
  data_cases(doc);
  struct Hand { const char* name; const char* want; std::function<Problems()> fn; };
  std::vector<Hand> hand = {
      {"category: other branch target", "reference", [] { return category(0, 0x180001b00, true); }},
      {"category: other immediate", "immediate", [] { return category(1, 0, false); }},
      {"build hashes pair one-to-one", nullptr, build_hashes},
      {"qualified names", nullptr, qualified_names},
      {"definition names", nullptr, definition_names},
      {"destructor pairing", nullptr, destructor_pairing},
      {"folded annotations", nullptr, folded_annotations},
      {"instruction diff", nullptr, instruction_diff},
      {"linear matcher", nullptr, [&] { return linear_matcher(doc); }},
      {"leaf extent", nullptr, leaf_extent_case},
      {"decode memo", nullptr, [&] { return decode_case(doc); }},
      {"local static names", nullptr, local_static_names},
      {"stub leaves its original open", nullptr, stub_pairing},
      {"GLOBAL bytes checked", nullptr, global_bytes},
      {"replay key", nullptr, replay_key},
      {"failed inference taken back", "reference", failed_inference},
      {"other static, owner compared later", "reference", [] { return prebound_static(false); }},
      {"other static, owner compared first", "reference", [] { return prebound_static(true); }},
      {"addend inside an annotated object", nullptr, [] { return addend_across_annotation(0x10); }},
      {"addend reaching another annotation", "reference", [] { return addend_across_annotation(0x20); }},
      {"ignored annotations reported", nullptr, ignored_annotations},
      {"malformed unwind chain ends", nullptr, malformed_unwind},
      {"unit: SHA-256 paths agree", nullptr, sha256_paths},
      {"unit: line splitting", nullptr, line_splitting},
      {"local static paired by consensus", nullptr, consensus_static},
      {"callee folded in the original, same code", nullptr, [] { return folded_original(true); }},
      {"callee folded in the original, other code", "reference", [] { return folded_original(false); }},
  };
  std::set<std::string> written;
  for (auto& h : hand) {
    written.insert(h.name);
    Problems probs;
    bool ok;
    std::string note;
    try {
      probs = h.fn();
      ok = verdict(h.want, probs);
      if (!ok && !probs.empty()) note = probs[0].second.substr(0, 120);
    } catch (std::exception& e) {
      ok = false;
      note = std::string("ERROR ") + e.what();
    }
    report(h.name, h.want, probs, ok, note);
  }
  for (auto& o : doc["other"].arr)
    if (!written.count(o.as_str())) { ++failures; std::printf("BAD %s: listed under \"other\" but not written out\n", o.as_str().c_str()); }
  std::printf("%zu cases, %d failures\n", doc["cases"].arr.size() + hand.size(), failures);
  return failures;
}
