// Acceptance tests of the comparison engine:
//   verifier-tests [fixtures.json] [-v]       exit code = number of failures
// Each case in tests/data/fixtures.json is a pair of small synthetic PE images (the original and a rebuild laid
// out at other addresses), the two functions to compare, the symbol mapping the comparer's hooks answer from,
// and the exact problems the comparison must report (none for a MATCH). The cases listed under "other" there are
// written out below (pairing, names, annotation parser, report diff), plus a few unit checks.
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "annotations.hpp"
#include "code_store.hpp"
#include "compare.hpp"
#include "content_hash.hpp"
#include "inputs.hpp"
#include "json.hpp"
#include "names.hpp"
#include "pairing.hpp"
#include "replay.hpp"
#include "report.hpp"
#include "sha256.hpp"
#include "source_cache.hpp"
#include "verify.hpp"

#ifndef VERIFIER_FIXTURES
#define VERIFIER_FIXTURES "tests/data/fixtures.json"
#endif

using namespace verifier;
using json::Value;

namespace {

using NameMap = std::unordered_map<u64, std::string_view>;
Symbols symbols_at(std::vector<u64> vas) {  // a symbol with an empty name at each address, in address order
  std::sort(vas.begin(), vas.end());
  std::vector<std::pair<u64, std::string_view>> syms;
  for (u64 v : vas) syms.emplace_back(v, "");
  return Symbols(syms);
}
NameOf name_of(const NameMap& m) {  // a lookup in m ("" for none)
  return [&m](u64 va) {
    auto it = m.find(va);
    return it == m.end() ? std::string_view() : it->second;
  };
}

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
  return {{BASE + TEXT, BASE + RDATA, 0x60000020},
          {BASE + RDATA, BASE + DATA, 0x40000040},
          {BASE + DATA, BASE + END, 0xC0000040}};
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
  for (auto& p : probs)
    if (p.first == want) return true;
  return false;
}

// -- data-driven cases ------------------------------------------------------------------------------------

Key key_of(const std::string& kind, const Value& v) {
  if (kind == "va") return Key::of_va(u64(v.as_int()));
  static const std::map<std::string, Key::Kind> kinds{{"const", Key::CONST}, {"str", Key::STR},
                                                      {"td", Key::TD},       {"ti", Key::TI},
                                                      {"vbt", Key::VBT},     {"unresolved", Key::UNRESOLVED}};
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
    imports[u64(i.arr[0].as_int())] =
        Import{i.arr[1].as_str(), i.arr[2].is_null() ? "" : i.arr[2].as_str(), u32(i.arr[3].as_int())};
  return Image::from_parts(BASE, mem, sections(), pdata, relocs, imports);
}

std::vector<u64> u64s(const Value* v) {
  std::vector<u64> out;
  if (v)
    for (auto& x : v->arr) out.push_back(u64(x.as_int()));
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
  NameMap names;
  for (auto& n : c["names"].arr) names[u64(n.arr[0].as_int())] = n.arr[1].as_str();
  auto resolve = [keys](u64 t) {
    auto it = keys->find(t);
    return it != keys->end() ? it->second : Key::named(Key::UNRESOLVED, hex(t));
  };
  // what the case says beyond its two images
  struct DataContext : ComparerContext {
    std::map<u64, std::vector<u64>> folded, refs;
    std::map<u64, int> folded_locals_;
    std::map<u64, std::optional<std::vector<u64>>> home;
    std::map<u64, u64> same_code, orig_ends;
    std::vector<std::pair<u64, u64>> padding;
    std::vector<u64> local, literals, starts, named, annotated;
    std::shared_ptr<std::map<u64, Key>> keys;
    const Image* R = nullptr;
    std::vector<u64> alternates(u64 t) const override {
      auto it = folded.find(t);
      return it == folded.end() ? std::vector<u64>() : it->second;
    }
    std::optional<std::pair<u64, u64>> local_base(u64 t) const override {
      for (u64 s : local)
        if (s <= t && t < s + 16) return std::make_pair(s, t - s);
      return std::nullopt;
    }
    int folded_locals(u64 t) const override {
      auto it = folded_locals_.find(t);
      return it == folded_locals_.end() ? 1 : it->second;
    }
    std::optional<std::vector<u64>> static_home(u64 t) const override {
      auto it = home.find(t);
      return it == home.end() ? std::nullopt : it->second;
    }
    u64 orig_object_end(u64 t) const override {
      auto it = orig_ends.find(t);
      return it == orig_ends.end() ? t : it->second;
    }
    bool orig_padding(u64 t) const override {
      for (auto& [lo, hi] : padding)
        if (lo <= t && t < hi) return true;
      return false;
    }
    std::vector<u64> orig_refs(u64 f) override {
      auto it = refs.find(f);
      return it == refs.end() ? std::vector<u64>() : it->second;
    }
    bool infer(u64 o_t, u64 r_t) override {
      auto it = same_code.find(r_t);
      return it != same_code.end() && it->second == o_t;
    }
    std::optional<std::pair<u64, Key>> literal_at(u64 t) const override {
      for (u64 v : literals) {
        Key k = keys->at(v);
        if (v <= t && i64(t - v) < literal_size(*R, v, k)) return std::make_pair(v, k);
      }
      return std::nullopt;
    }
    bool symbol_start(u64 t) const override { return std::binary_search(starts.begin(), starts.end(), t); }
    u64 span(u64 t) const override {
      if (starts.empty()) return ComparerContext::span(t);
      for (u64 s : starts)
        if (s > t) return s - t;
      return 0x100;
    }
    std::optional<u64> containing(u64 t) const override {
      if (starts.empty()) return ComparerContext::containing(t);
      std::optional<u64> best;
      for (u64 s : starts)
        if (s <= t) best = s;
      return best;
    }
    bool orig_named(u64 t) const override { return std::find(named.begin(), named.end(), t) != named.end(); }
    bool annotated_between(u64 lo, u64 hi) const override {
      for (u64 a : annotated)
        if (lo < a && a <= hi) return true;
      return false;
    }
    std::optional<u64> end_of_previous(u64 t) const override {
      if (!std::binary_search(starts.begin(), starts.end(), t)) return std::nullopt;
      for (auto it = starts.rbegin(); it != starts.rend(); ++it) {
        u64 p = *it;
        auto k = keys->find(p);
        if (p < t && k != keys->end() && k->second.kind == Key::VA) return k->second.va + t - p;
      }
      return std::nullopt;
    }
  } dc;
  for (auto& f : m["folded"].arr) dc.folded[u64(f.arr[0].as_int())] = u64s(&f.arr[1]);
  for (auto& f : m["refs"].arr) dc.refs[u64(f.arr[0].as_int())] = u64s(&f.arr[1]);
  for (auto& f : m["folded_locals"].arr) dc.folded_locals_[u64(f.arr[0].as_int())] = int(f.arr[1].as_int());
  for (auto& h : m["home"].arr)
    dc.home[u64(h.arr[0].as_int())] = h.arr[1].is_null() ? std::nullopt : std::optional(u64s(&h.arr[1]));
  for (auto& x : m["same_code"].arr) dc.same_code[u64(x.arr[0].as_int())] = u64(x.arr[1].as_int());
  if (auto* e = m.get("orig_ends"))
    for (auto& x : e->arr) dc.orig_ends[u64(x.arr[0].as_int())] = u64(x.arr[1].as_int());
  if (auto* p = m.get("padding"))
    for (auto& x : p->arr) dc.padding.emplace_back(u64(x.arr[0].as_int()), u64(x.arr[1].as_int()));
  dc.local = u64s(m.get("local"));
  dc.literals = u64s(m.get("literals"));
  dc.starts = u64s(m.get("starts"));
  dc.named = u64s(m.get("named"));
  dc.annotated = u64s(m.get("annotated"));
  std::sort(dc.starts.begin(), dc.starts.end());
  dc.keys = keys;
  dc.R = &R;
  Comparer cmp(&O, &R, resolve, &vtables, name_of(names), &dc);
  if (auto* pb = m.get("pre_bound")) {
    u64 rb = u64(pb->arr[0].as_int()), ob = u64(pb->arr[1].as_int());
    cmp.bound.set(rb, ob);
    cmp.bound_o.set(ob, rb);
  }
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

Problems bad_if(bool bad, const std::string& cat, const std::string& why) {
  return bad ? Problems{{cat, why}} : Problems{};
}

Op opm(const char* base, i64 disp, int size) {
  Op o{};
  o.k = Op::M;
  o.base = reg_named(base);
  o.scale = 1;
  o.v = disp;
  o.size = size;
  return o;
}
Op opi(i64 v) {
  Op o{};
  o.k = Op::I;
  o.v = v;
  return o;
}
Op opsym(Key k) {
  Op o{};
  o.k = Op::SYM;
  o.key = std::move(k);
  return o;
}
Op opr(const char* r) {
  Op o{};
  o.k = Op::R;
  o.base = reg_named(r);
  return o;
}
Op oprel(i64 v) {
  Op o{};
  o.k = Op::REL;
  o.v = v;
  return o;
}

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
  auto rtti_of = [](const Bytes& name, u32 off) {
    Rtti r;
    r.present = true;
    r.name = name;
    r.off = off;
    return r;
  };
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
      {"public: virtual void * __cdecl A::B::`scalar deleting destructor'(unsigned int)",
       "A::B::`scalar deleting destructor'"},
      {"[thunk]:public: virtual void * __cdecl A::B::`scalar deleting destructor'`adjustor{8}' (unsigned int)",
       "A::B::`scalar deleting destructor'`adjustor{8}'"},
      {"[thunk]:public: virtual void * __cdecl A::C::`vector deleting destructor'`adjustor{8}' (unsigned int)",
       "A::C::`vector deleting destructor'`adjustor{8}'"},
      {"public: int __cdecl A::B::Get(void)const ", "A::B::Get"},
      {"public: void __cdecl N::Vector<struct N::Id const * __ptr64>::PushBack(struct N::Id const * __ptr64 const & "
       "__ptr64,bool) __ptr64",
       "N::Vector<N::Id const*>::PushBack"},
      {"public: virtual void * __ptr64 __cdecl N::Vector<struct N::Id const * __ptr64>::`scalar deleting "
       "destructor'(unsigned int) __ptr64",
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
      {"[thunk]:public: virtual void * __ptr64 __cdecl N::A::`vector deleting destructor'`vtordisp{4294967292,0}' "
       "(unsigned int) __ptr64",
       "N::A::`vector deleting destructor'`vtordisp{4294967292,0}'"},
      {"public: void __cdecl N::E<class N::I * __ptr64>::`vbase destructor'(void) __ptr64",
       "N::E<N::I*>::`vbase destructor'"},
      {"public: void __cdecl `anonymous namespace'::S::f(int) __ptr64", "`anonymous namespace'::S::f"},
      {"int (__cdecl*__cdecl select_printer(struct box * __ptr64))(struct _iobuf * __ptr64,int)", "select_printer"},
  };
  Problems bad;
  for (auto& [u, want] : cases)
    if (qualified(u) != want) bad.push_back({"name", u + " -> " + qualified(u)});
  std::vector<std::pair<std::string, std::string>> owners = {
      {"int `int __cdecl N::f(void)'::`2'::x", "N::f"},
      {"unsigned __int64 `__local_stdio_printf_options'::`2'::_OptionsStorage", "__local_stdio_printf_options"},
  };
  for (auto& [u, want] : owners)
    if (static_owner(u) != want) bad.push_back({"static owner", u + " -> " + static_owner(u)});
  std::vector<std::pair<std::string, std::string>> sigs = {
      {"void __cdecl operator delete(void * __ptr64)", "(void*)"},
      {"void __cdecl operator delete(void * __ptr64,unsigned __int64)", "(void*,unsigned __int64)"},
      {"public: __cdecl N::S::S(class N::S const & __ptr64) __ptr64", "(S const&)"},
      {"public: int __cdecl A::B::Get(void)const ", "(void)"},
      {"public: bool __cdecl N::S::operator<(class N::S const & __ptr64)const __ptr64", "(S const&)"},
      {"int (__cdecl*__cdecl select_printer(struct box * __ptr64))(struct _iobuf * __ptr64,int)", "(box*)"},
      {"void __cdecl f(void (__cdecl*)(int))", "(void (__cdecl*)(int))"},
  };
  for (auto& [u, want] : sigs)
    if (signature(u) != want) bad.push_back({"signature", u + " -> " + signature(u)});
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

// names far longer than the recursion of a backtracking regex engine allows (real builds have undecorated
// names tens of thousands of characters long)
Problems long_names() {
  const std::string x(200000, 'x');
  Problems bad;
  std::string dyn = "void __cdecl `dynamic initializer for 'N::g<" + x + ">''(void)";
  if (qualified(dyn) != "`dynamic initializer for 'N::g<" + x + ">''") bad.push_back({"name", "dynamic initializer"});
  std::string local =
      "void __cdecl `int __cdecl N::f<" + x + ">(void)'::`2'::`dynamic atexit destructor for 's''(void)";
  if (qualified(local) != "N::f<" + x + ">::`dynamic atexit destructor for 's''")
    bad.push_back({"name", "local atexit destructor"});
  std::string params;
  for (int i = 0; i < 20000; ++i) params += i ? ",struct box * __ptr64" : "struct box * __ptr64";
  std::string fp = "int (__cdecl*__cdecl select_printer(" + params + "))(struct _iobuf * __ptr64,int)";
  if (qualified(fp) != "select_printer") bad.push_back({"name", "function returning a function pointer"});
  if (global_decl_name("static int " + x + "[4][2] = {};") != x) bad.push_back({"global", "declaration"});
  if (global_decl_name(x + " " + x)) bad.push_back({"global", "no declaration"});
  if (class_decl_name("class __declspec(novtable) N::" + x + " : public B {") != "N::" + x)
    bad.push_back({"class", "declaration"});
  if (definition_name("__declspec(noinline) void N::" + x + "(int)") != "N::" + x)
    bad.push_back({"name", "definition"});
  return bad;
}

Problems destructor_pairing() {
  std::string dd = "N::X::`scalar deleting destructor'";
  auto both = [](const std::string&) { return true; };
  std::function<bool(const std::string&)> only_dd = [&](const std::string& n) { return n == dd; };
  std::function<bool(const std::string&)> no_dd = [&](const std::string& n) { return n != dd; };
  struct C {
    bool in_slot;
    std::function<bool(const std::string&)> has;
    std::string want;
  };
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
  std::string qualified(std::string_view d) const override {
    return fake.qualified ? fake.qualified(d) : Rebuilt::qualified(d);
  }
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
  reb.symbols = Symbols({{0x100, "?A@@YAXXZ"}, {0x100, "?B@@YAXXZ"}, {0x200, "?C@@YAXXZ"}});
  reb.fake.qualified = [](std::string_view n) { return std::string(n.substr(1, 1)); };
  std::map<std::string, u64> m{{"A", 0x100}, {"B", 0x100}, {"C", 0x200}};
  reb.fake.lookup = [m](const std::string& k, auto&, bool) { return fixed_lookup(m, k); };
  std::vector<Annotation> anns = {{"FUNCTION", 0x1000, "A", {}, "a.cpp", 1},
                                  {"FUNCTION", 0x2000, "B", {}, "b.cpp", 1},
                                  {"FUNCTION", 0x3000, "C", {}, "c.cpp", 1}};
  Pairing p(orig, reb, anns);
  auto a1 = p.alternates(0x100), a2 = p.alternates(0x200);
  bool ok = std::set<u64>(a1.begin(), a1.end()) == std::set<u64>{0x1000, 0x2000} && a2.empty();
  return bad_if(!ok, "alternates", "wrong alternates");
}

Problems instruction_diff() {
  auto insns = [](std::vector<u32> offsets) { return offsets; };
  Toks o_toks = {
      {"push", {opr("rbx")}}, {"je", {oprel(7)}}, {"call", {opsym(Key::of_va(0x180001000))}}, {"pop", {opr("rbx")}}};
  Toks r_toks = {{"push", {opr("rbx")}},
                 {"je", {oprel(10)}},
                 {"nop", {}},
                 {"call", {opsym(Key::named(Key::UNRESOLVED, "Foo"))}},
                 {"pop", {opr("rbx")}}};
  auto oi = insns({0, 1, 3, 7}), ri = insns({0, 1, 3, 4, 10});
  NameMap names{{0x180001000, "Bar"}};
  Problems bad;
  auto got = insn_diff(oi, ri, o_toks, r_toks, name_of(names), 1);
  std::vector<std::string> want = {"@1", "  je <+0x7>", "- call Bar", "+ nop", "+ call Foo", "  pop rbx"};
  if (got != want) bad.push_back({"diff", join(got, " | ")});
  r_toks[1] = {"je", {oprel(0)}};
  got = insn_diff(oi, ri, o_toks, r_toks, name_of(names), 0);
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
    auto m = find_longest_match(a, b, size_t(r[0].as_int()), size_t(r[1].as_int()), size_t(r[2].as_int()),
                                size_t(r[3].as_int()));
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
  auto times = [](const std::string& s, int n) {
    std::string r;
    for (int i = 0; i < n; ++i) r += s;
    return r;
  };
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

// the same code decoded at two addresses: sizes, mnemonics, absolute branch targets and RIP-relative operands
// follow from the encoding
Problems decode_case() {
  Bytes code = unhex("e8f0ffffff7405e2fc488d0d10000000ff2510000000e9a0ffffffb801000000c3");
  struct Want {
    int size;
    const char* mnemonic;
    i64 target;
  };  // target: branch target or RIP displacement
  std::vector<Want> want = {{5, "call", -0x10}, {2, "jz", 5},      {2, "loop", -4}, {7, "lea", 0x10},
                            {6, "jmp", 0x10},   {5, "jmp", -0x60}, {5, "mov", 0},   {1, "ret", 0}};
  Problems bad;
  for (u64 address : {u64(0x180001000), u64(0x180123f30)}) {
    auto insns = decode_linear(code, address);
    bool ok = insns.size() == want.size();
    u64 at = address;
    for (size_t i = 0; ok && i < insns.size(); ++i) {
      const Insn& x = insns[i];
      const Want& w = want[i];
      u64 next = at + u64(w.size);
      ok = x.address == at && x.size == w.size && x.mnemonic == w.mnemonic;
      if (ok && x.branches() && !x.ops.empty() && x.ops[0].type == OP_IMM) ok = x.ops[0].imm() == i64(next) + w.target;
      if (ok && !x.ops.empty() && x.ops[x.ops.size() - 1].type == OP_MEM)
        ok = x.ops[x.ops.size() - 1].base() == reg_rip() && x.ops[x.ops.size() - 1].disp() == w.target;
      at = next;
    }
    if (!ok) bad.push_back({"decode", "at " + hex(address)});
  }
  return bad;
}

Problems local_static_names() {
  std::vector<std::pair<std::string, bool>> cases = {
      {"?$S3@?1??GetSharedMutex@@YAPEAVmutex@std@@XZ@4IA", true},
      {"?unpacked@?1??unpack_language@@YAPEADG@Z@4PADA", true},
      {"?table@?BA@??read_record@@YAHPEAUrecord@@PEAX@Z@4QBU<unnamed-type-table>"
       "@?BA@??1@YAH01@Z@B",
       true},
      {"?g_foo@@3HA", false},
      {"?x@Cls@@2HA", false},
      {"?x@?A0x12345678@ns@@3HA", false},
  };
  Problems bad;
  for (auto& [n, want] : cases)
    if ((local_static_match(n) != 0) != want) bad.push_back({"local static", n});
  return bad;
}

Problems stub_pairing() {
  Original orig;
  FakeRebuilt reb;
  reb.symbols = Symbols({{0x100, "sub_1000"}, {0x200, "A"}});
  std::map<std::string, u64> m{{"sub_1000", 0x100}, {"A", 0x200}};
  reb.fake.lookup = [m](const std::string& k, auto&, bool) { return fixed_lookup(m, k); };
  Pairing p(orig, reb, {{"STUB", 0x1000, "sub_1000", {}, "s.cpp", 1}, {"FUNCTION", 0x2000, "A", {}, "a.cpp", 1}});
  bool ok = !p.paired_o.count(0x1000) && p.paired_o.count(0x2000);
  return bad_if(!ok, "paired", "stub/function paired wrongly");
}

Problems global_bytes() {
  Side o(0), r(0x240);
  u64 oa = o.put(RDATA, Bytes("STANDARD\0", 9)), ob = o.put(RDATA, Bytes("EXPANDED\0", 9)),
      ow = o.put(DATA, Bytes("\1\0\0\0", 4));
  u64 ra = r.put(RDATA, Bytes("STANDARD\0", 9)), rb = r.put(RDATA, Bytes("EXPANDED\0", 9)),
      rw = r.put(DATA, Bytes("\2\0\0\0", 4));
  Image O = o.image(), R = r.image();
  std::map<std::string, u64> names{{"g_std", ra}, {"g_exp", rb}, {"g_w", rw}};
  std::vector<Annotation> anns = {{"GLOBAL", oa, "g_std", {}, "a.cpp", 1},
                                  {"GLOBAL", oa, "g_exp", {}, "a.cpp", 2},
                                  {"GLOBAL", ow, "g_w", {}, "a.cpp", 3},
                                  {"GLOBAL", ob, "g_gone", {}, "a.cpp", 4},
                                  {"FUNCTION", ob, "g_std", {}, "a.cpp", 5}};
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
  for (auto& g : check_globals(anns, lookup, reb_to_orig, c)) got.push_back(g.ann->name);
  return bad_if(got != std::vector<std::string>{"g_exp"}, "globals", "reported " + join(got, ","));
}

Problems replay_key() {
  namespace fs = std::filesystem;
  fs::path d = fs::temp_directory_path() / ("verifier-test-" + unique_suffix());
  fs::create_directories(d / "src");
  Problems bad;
  std::map<std::string, std::string> files{{"x.dll", (d / "x.dll").string()},
                                           {"x.map", (d / "x.map").string()},
                                           {"matched.txt", (d / "matched.txt").string()},
                                           {"src/a.cpp", (d / "src" / "a.cpp").string()}};
  Args a;
  a.rebuilt = files["x.dll"];
  a.map = files["x.map"];
  a.matched = files["matched.txt"];
  a.src = {(d / "src").string()};
  Config p;
  std::vector<std::string> args;
  auto write = [](const std::string& path, const std::string& text) { std::ofstream(path, std::ios::binary) << text; };
  std::vector<std::pair<std::string, std::function<void()>>> changes;
  for (auto& [n, path] : files) changes.emplace_back(n, [&write, path = path] { write(path, "2"); });
  changes.emplace_back("added source", [&] { write((d / "src" / "b.h").string(), ""); });
  for (auto& [name, change] : changes) {
    for (auto& [n, path] : files) write(path, "1");
    args = {"--check"};
    std::error_code ec;
    fs::remove(d / "src" / "b.h", ec);
    std::string key = run_key(a, p, "verifier");
    if (run_key(a, p, "verifier") != key) bad.push_back({"replay", "the key of the same inputs differs"});
    change();
    if (run_key(a, p, "verifier") == key) bad.push_back({"replay", "the key ignores " + name});
  }
  if (run_key(a, p, "verifier") == run_key(a, p, "another verifier"))
    bad.push_back({"replay", "the key ignores the verifier"});
  std::error_code removed;
  fs::remove(d / "src" / "b.h", removed);  // the last change's
  // the command: its arguments, the root and the configuration's contents
  p.file = (d / "verifier.conf").string();
  write(p.file, "a = 1");
  std::string command = command_key(args, p);
  if (command_key(args, p) != command) bad.push_back({"replay", "the command of the same run differs"});
  if (command_key({"--check", "--json"}, p) == command) bad.push_back({"replay", "the command ignores the arguments"});
  Config q = p;
  q.root = "elsewhere";
  if (command_key(args, q) == command) bad.push_back({"replay", "the command ignores the root"});
  write(p.file, "a = 2");
  if (command_key(args, p) == command) bad.push_back({"replay", "the command ignores the configuration's contents"});
  // a run that computes the key at its end takes the sources from parsing them: the same key, the files that cannot
  // hold an annotation included
  fs::create_directories(d / "src" / "sub");
  write((d / "src" / "notes.txt").string(), "x");
  write((d / "src" / "sub" / "c.cpp").string(), "// FUNCTION: EXAMPLE 0x10\nvoid f() {}\n");
  std::vector<std::string> seen;
  std::map<std::string, std::string> hashes;
  std::vector<ListedFile> listed;
  parse_annotations(a.src, "EXAMPLE", nullptr, [&](const ListedFile& f, std::string_view data) {
    seen.push_back(f.path);
    listed.push_back(f);
    hashes[f.path] = content_hash(data);
  });
  auto hash = [&](const std::string& f) {
    auto it = hashes.find(f);
    return it != hashes.end() ? it->second : fs::exists(f) ? content_hash_file_if_present(f) : std::string();
  };
  if (seen.size() != 3 || run_key(a, p, "verifier", seen, hash) != run_key(a, p, "verifier"))
    bad.push_back({"replay", "the key from parsing the sources differs from the walked one"});
  // and the stamps from that listing are the listed ones (an hour old here: none are recent)
  auto hour_ago = fs::file_time_type::clock::now() - std::chrono::hours(1);
  for (auto& f : listed) fs::last_write_time(f.path, hour_ago);
  for (auto* f : {&a.rebuilt, &a.map}) fs::last_write_time(*f, hour_ago);
  fs::last_write_time(*a.matched, hour_ago);
  listed.clear();
  parse_annotations(a.src, "EXAMPLE", nullptr, [&](const ListedFile& f, std::string_view) { listed.push_back(f); });
  std::string stamps = stamp_key(a, p, "");
  if (stamps.empty() || stamp_key(a, p, "", listed, two_seconds_ago()) != stamps)
    bad.push_back({"replay", "the stamps from parsing the sources differ from the listed ones"});
  // the original: by its contents without a cache, by the snapshot's key (size, time, configured hash) with one
  p.original = (d / "orig.dll").string();
  write(p.original, "1");
  std::string plain = run_key(a, p, "verifier");
  write(p.original, "2");
  if (run_key(a, p, "verifier") == plain) bad.push_back({"replay", "the key ignores the original's contents"});
  p.cache_dir = (d / "cache").string();
  std::string cached = run_key(a, p, "verifier");
  if (cached == plain) bad.push_back({"replay", "the key with a cache is the one without"});
  write(p.original, "22");
  if (run_key(a, p, "verifier") == cached) bad.push_back({"replay", "the key with a cache ignores the original"});
  // inputs changed within two seconds: no snapshot key (the snapshot is neither used nor written)
  if (!Original::snapshot_key(p).empty())
    bad.push_back({"replay", "the snapshot's key trusts an input written just now"});
  for (auto* f : p.snapshot_inputs())
    if (!f->empty() && fs::exists(*f))
      fs::last_write_time(*f, fs::file_time_type::clock::now() - std::chrono::hours(1));
  if (Original::snapshot_key(p).empty()) bad.push_back({"replay", "no snapshot key for inputs an hour old"});
  cached = run_key(a, p, "verifier");
  p.original_sha256 = "ab";
  if (run_key(a, p, "verifier") == cached || Original::snapshot_key(p) == [&] {
        Config q = p;
        q.original_sha256 = "cd";
        return Original::snapshot_key(q);
      }())
    bad.push_back({"replay", "the snapshot's key ignores the configured hash"});
  std::error_code ec;
  fs::remove_all(d, ec);
  return bad;
}

Problems failed_inference() {
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
            {{"GLOBAL", fo.X, "X", {}, "x.cpp", 1},
             {"FUNCTION", fo.G, "G", {}, "g.cpp", 1},
             {"FUNCTION", fo.F, "F", {}, "f.cpp", 1}});
  Image O = o.image(), R = r.image();
  struct InferOnly : ComparerContext {  // the pairing's inference, nothing else known
    Pairing& p;
    explicit InferOnly(Pairing& x) : p(x) {}
    bool infer(u64 a, u64 b) override { return p.infer(a, b); }
  } infer_only(p);
  p.use(std::make_unique<Comparer>(&O, &R, [&p](u64 t) { return p.resolve_symbol(t); }, nullptr, nullptr, &infer_only));
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
  std::vector<u64> vas;
  for (auto& [n, f] : fns) {
    run.orig.functions.set(IdaFunction{f.first, 7, "", false, false});
    vas.push_back(f.second);
    m[n] = f.second;
    anns.push_back({"FUNCTION", f.first, n, {}, n + ".cpp", 1});
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
  run.orig.functions.set(IdaFunction{oo, 4, "", false, false});
  run.orig.functions.set(IdaFunction{oG, 6, "", false, false});
  auto& reb = run.reb;
  reb.symbols = symbols_at({ra, rb, rG});
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
  reb.symbols = Symbols({{rg, "?g@@3HA"}, {ry, "?y@@3HA"}});
  reb.fake.qualified = [](std::string_view n) { return std::string(n.substr(1, 1)); };
  std::map<std::string, u64> m{{"g", rg}, {"y", ry}};
  reb.fake.lookup = [m](const std::string& k, auto&, bool) { return fixed_lookup(m, k); };
  reb.fake.local_base = [](u64) { return std::optional<std::pair<u64, u64>>(); };
  Pairing p(orig, reb, {{"GLOBAL", og, "g", {}, "g.cpp", 1}, {"GLOBAL", oy, "y", {}, "y.cpp", 1}});
  p.use(std::make_unique<Comparer>(nullptr, nullptr, [&p](u64 t) { return p.resolve(t); }));
  Key got = p.resolve(rg + off);
  return bad_if(!got.is_va(og + off), "reference", "g+" + hex(off) + " resolves to " + got.text());
}

// the name cache file: what a run stores is what the next run reads (in the order of its map, new names added,
// ids equal exactly when the strings are), and a damaged file is ignored. Names without a leading '?' need no
// undname.
Problems name_cache() {
  namespace fs = std::filesystem;
  fs::path d = fs::temp_directory_path() / ("verifier-names-" + unique_suffix());
  fs::create_directories(d);
  std::string file = (d / "names.bin").string();
  auto infos_of = [](NameCache& nc, const std::vector<std::string_view>& names) {
    std::vector<std::string> out;
    for (auto& ids : nc.load(names)) {
      NameInfo ni = nc.info(ids);
      out.push_back(std::string(ni.decorated) + "|" + std::string(ni.qualified) + "|" + std::string(ni.signature) +
                    "|" + std::string(ni.owner) + "|" + std::string(nc.text(ids.last1)) + "|" +
                    std::string(nc.text(ids.last2)));
    }
    return out;
  };
  Problems bad;
  std::vector<std::string_view> first = {"N::A::f", "N::B::f", "g", "N::A::f", "M::N::A::f"};
  std::vector<std::string_view> second = {"h", "N::B::f", "M::N::A::f", "N::A::f", "N::C::f"};
  std::vector<std::string> want1, want2;
  {
    NameCache nc(file, "key", "");
    want1 = infos_of(nc, first);
    nc.save();
  }
  {
    NameCache nc(file, "key", "");
    if (infos_of(nc, first) != want1) bad.push_back({"names", "reloaded entries differ"});
    auto infos = nc.load(second);
    want2 = infos_of(nc, second);
    nc.save();
    // the same qualified name, the same id; f is every name's last component
    if (infos[1].last1 != infos[3].last1 || infos[1].qualified == infos[3].qualified ||
        nc.text(infos[1].qualified) != nc.info(infos[1]).qualified)
      bad.push_back({"names", "ids"});
    if (!nc.id_of("f") || nc.id_of("no such string")) bad.push_back({"names", "id_of"});
  }
  {
    NameCache nc(file, "key", "");
    if (infos_of(nc, second) != want2) bad.push_back({"names", "entries after adding names differ"});
  }
  {
    NameCache nc(file, "other key", "");  // another undname: the file is not used
    if (nc.string_count() != 0) bad.push_back({"names", "file of another key read"});
  }
  {
    // a run replaces the file while another has it mapped: the other goes on reading the old one
    NameCache reader(file, "key", "");
    NameCache writer(file, "key", "");
    writer.load({"i"});
    writer.save();
    if (infos_of(reader, second) != want2) bad.push_back({"names", "the mapped file changed"});
  }
  {
    NameCache nc(file, "key", "");
    if (!nc.id_of("i")) bad.push_back({"names", "not replaced while mapped"});
    nc.load(second);
    nc.save();
  }
  {
    // the names of other builds are kept after this build's, the most recent first, as many as this build has
    NameCache a(file, "key", "");
    a.load({"p", "q", "r"});
    a.save();
    NameCache b(file, "key", "");
    b.load({"s", "t"});
    if (b.has_new() != true || !b.id_of("p")) bad.push_back({"names", "has_new, or the old file read"});
    b.save();
    NameCache c(file, "key", "");
    c.load({"s", "t"});
    if (c.has_new() || !c.id_of("p") || !c.id_of("q") || c.id_of("r"))
      bad.push_back({"names", "other builds' names kept: not p, q only"});
    auto before = fs::last_write_time(file);
    c.save();  // starts with s, t and keeps two others: nothing to write
    if (fs::last_write_time(file) != before) bad.push_back({"names", "rewritten with nothing new"});
    NameCache e(file, "key", "");
    e.load({"p"});  // in the file, not first: a save puts it first
    if (e.has_new()) bad.push_back({"names", "a name of another build undecorated again"});
    e.save();
    NameCache f2(file, "key", "");
    f2.load({"p"});
    if (!f2.id_of("s") || f2.id_of("t")) bad.push_back({"names", "after reordering: not p then s"});
  }
  {
    NameCache nc(file, "key", "");
    nc.load(second);
    nc.save();
  }
  fs::resize_file(file, fs::file_size(file) - 3);
  {
    NameCache nc(file, "key", "");
    if (nc.string_count() != 0) bad.push_back({"names", "truncated file read"});
    if (infos_of(nc, second) != want2) bad.push_back({"names", "entries without the file differ"});
  }
  std::error_code ec;
  fs::remove_all(d, ec);
  return bad;
}

// a PE file on disk: loading lays it out at its virtual addresses, and an image laid out elsewhere (the cache's) reads
// the same tables from its headers
Problems file_layout() {
  namespace fs = std::filesystem;
  auto put = [](Bytes& b, size_t at, u64 v, int n) {
    for (int i = 0; i < n; ++i) b[at + i] = char(v >> (8 * i));
  };
  auto pe_file = [&](u64 base) {
    Bytes f(0x600, '\0');
    f[0] = 'M';
    f[1] = 'Z';
    put(f, 0x3c, 0x40, 4);
    f.replace(0x40, 4, Bytes("PE\0\0", 4));
    put(f, 0x44, 0x8664, 2);  // machine
    put(f, 0x46, 2, 2);       // sections
    put(f, 0x54, 0xf0, 2);    // optional header size
    put(f, 0x58, 0x20b, 2);   // PE32+
    put(f, 0x58 + 24, base, 8);
    put(f, 0x58 + 32, 0x1000, 4);  // section alignment
    put(f, 0x58 + 36, 0x200, 4);   // file alignment
    struct S {
      u32 vsize, va, rawsize, rawptr, ch;
    };
    S secs[2] = {{0x10, 0x1000, 0x200, 0x200, 0x60000020}, {0x2000, 0x2000, 0x200, 0x400, 0xc0000040}};
    for (int i = 0; i < 2; ++i) {
      size_t s = 0x148 + 40 * i;
      put(f, s + 8, secs[i].vsize, 4);
      put(f, s + 12, secs[i].va, 4);
      put(f, s + 16, secs[i].rawsize, 4);
      put(f, s + 20, secs[i].rawptr, 4);
      put(f, s + 36, secs[i].ch, 4);
    }
    for (size_t k = 0x200; k < 0x600; ++k) f[k] = char(k * 7 + 1);  // code and data, no zeros
    return f;
  };
  fs::path d = fs::temp_directory_path() / ("verifier-pe-" + unique_suffix());
  fs::create_directories(d);
  std::string path = (d / "x.dll").string();
  Bytes file = pe_file(0x180000000);
  std::ofstream(path, std::ios::binary) << file;
  Problems bad;
  Image im = Image::load(path);
  if (im.base != 0x180000000 || im.img.size() != 0x2200 || im.sections.size() != 2 ||
      im.bytes(0x180001000, 1) != file.substr(0x200, 1) || im.bytes(0x180000300, 1) != Bytes(1, '\0'))
    bad.push_back({"layout", "the image is not laid out at its virtual addresses"});
  auto buf = std::make_shared<Bytes>(im.img);
  Image same = Image::laid_out(im.headers, *buf, buf);
  if (same.img != im.img || same.sections.size() != 2 || same.base != im.base)
    bad.push_back({"layout", "a copy differs"});
  std::error_code ec;
  fs::remove_all(d, ec);
  return bad;
}

// the report's records, written as they are made, are the text json::dump gives for the same document
Problems report_writer() {
  using json::Value;
  auto strs = [](std::vector<std::string> v) {
    Value a = Value::array();
    for (auto& x : v) a.push(Value::str(x));
    return a;
  };
  std::vector<Result> rs(4);
  std::vector<Value> want(4, Value::object());
  rs[0].orig = "0x180001000";
  rs[0].name = "f";
  rs[0].kind = "FUNCTION";
  rs[0].src = "a.cpp:1";
  rs[0].status = "BADADDR";
  rs[0].overloads = {"(int)", "(char const*)"};
  for (auto& [k, v] : std::vector<std::pair<std::string, Value>>{{"orig", Value::str("0x180001000")},
                                                                 {"name", Value::str("f")},
                                                                 {"kind", Value::str("FUNCTION")},
                                                                 {"src", Value::str("a.cpp:1")},
                                                                 {"overloads", strs({"(int)", "(char const*)"})},
                                                                 {"status", Value::str("BADADDR")}})
    want[0].set(k, v);
  rs[1] = rs[0];
  rs[1].overloads = {"(int)"};
  rs[1].status = "LIBCODE";
  rs[1].linked = true;
  rs[1].lib = "x.lib";
  want[1] = Value::object();
  for (auto& [k, v] : std::vector<std::pair<std::string, Value>>{{"orig", Value::str("0x180001000")},
                                                                 {"name", Value::str("f")},
                                                                 {"kind", Value::str("FUNCTION")},
                                                                 {"src", Value::str("a.cpp:1")},
                                                                 {"status", Value::str("LIBCODE")}})
    want[1].set(k, v);
  Value lib = Value::array();
  lib.push(Value::str("x.lib"));
  lib.push(Value::null());
  want[1].set("library", lib);
  rs[2] = rs[1];
  rs[2].linked = false;
  rs[2].status = "MATCH";
  rs[2].compared = true;
  rs[2].osize = 16;
  rs[2].rsize = 16;
  want[2] = Value::object();
  for (auto& [k, v] : std::vector<std::pair<std::string, Value>>{{"orig", Value::str("0x180001000")},
                                                                 {"name", Value::str("f")},
                                                                 {"kind", Value::str("FUNCTION")},
                                                                 {"src", Value::str("a.cpp:1")},
                                                                 {"osize", Value::integer(16)},
                                                                 {"rsize", Value::integer(16)},
                                                                 {"status", Value::str("MATCH")},
                                                                 {"category", Value::null()},
                                                                 {"unresolved", Value::array()},
                                                                 {"problems", Value::array()}})
    want[2].set(k, v);
  rs[3] = rs[2];
  rs[3].status = "DIFF";
  rs[3].category = "regalloc";
  rs[3].unresolved = {"?g@@3HA"};
  rs[3].problems = {"code: \"x\"\n"};
  rs[3].first_diff = Result::FirstDiff{3, "mov eax, 1", "mov ecx, 1"};
  rs[3].has_diff = true;
  want[3] = Value::object();
  Value fd = Value::object();
  fd.set("index", Value::integer(3));
  fd.set("orig", Value::str("mov eax, 1"));
  fd.set("rebuilt", Value::str("mov ecx, 1"));
  for (auto& [k, v] : std::vector<std::pair<std::string, Value>>{{"orig", Value::str("0x180001000")},
                                                                 {"name", Value::str("f")},
                                                                 {"kind", Value::str("FUNCTION")},
                                                                 {"src", Value::str("a.cpp:1")},
                                                                 {"osize", Value::integer(16)},
                                                                 {"rsize", Value::integer(16)},
                                                                 {"status", Value::str("DIFF")},
                                                                 {"category", Value::str("regalloc")},
                                                                 {"unresolved", strs({"?g@@3HA"})},
                                                                 {"problems", strs({"code: \"x\"\n"})},
                                                                 {"first_diff", fd},
                                                                 {"diff", Value::array()}})
    want[3].set(k, v);
  Problems bad;
  for (size_t n : {size_t(0), size_t(4)}) {  // as run() writes the document
    std::string got = "{\n  \"results\": ";
    for (size_t k = 0; k < n; ++k) {
      got += k == 0 ? "[\n    " : ",\n    ";
      write_result(got, rs[k], 2);
    }
    got += n == 0 ? "[]" : "\n  ]";
    got += ",\n  \"matched\": ";
    json::put_value(got, Value::integer(1), 1);
    got += "\n}\n";
    Value doc = Value::object(), arr = Value::array();
    for (size_t k = 0; k < n; ++k) arr.push(want[k]);
    doc.set("results", arr);
    doc.set("matched", Value::integer(1));
    if (got != json::dump(doc)) bad.push_back({"report", std::to_string(n) + " results: the text differs"});
  }
  return bad;
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
  if (got != std::vector<std::pair<std::string, int>>{{"a.cpp", 1}, {"b.cpp", 1}, {"c.cpp", 1}})
    bad.push_back({"ignored", "wrong set"});
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
  c.unwind_info(R.pdata_at(fr + 8)->unwind, R.pdata_at(fr + 8)->unwind, fo, fo + 13, fr, fr + 13, 0);
  return bad_if(!(end && *end == fr + 8), "extent", end ? hex(*end) : "None");
}

// unit check: the SHA-256 paths agree (SHA instructions where the CPU has them, portable code), and known digests
Problems sha256_paths() {
  Problems bad;
  if (sha256_hex("abc") != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    bad.push_back({"sha256", "abc"});
  if (sha256_hex("") != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    bad.push_back({"sha256", "empty"});
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

// the stamp key: the same for the same metadata, another when a file's time or size or the configuration's contents
// change, and none while an input is younger than two seconds
Problems content_hashes() {
  Problems bad;
  // XXH64's published values (the 39-byte input runs through the 32-byte stripes)
  const std::pair<const char*, u64> known[] = {{"", 0xEF46DB3751D8E999ull},
                                               {"a", 0xD24EC4F1A98C6E5Bull},
                                               {"abc", 0x44BC2CF5AD770999ull},
                                               {"Nobody inspects the spammish repetition", 0xFBCEA83C8A378BF1ull}};
  for (auto& [text, h] : known)
    if (xxh64(text, 0) != h) bad.push_back({"content hash", std::string("xxh64 of \"") + text + "\""});
  if (content_hash("abc").size() != 32 || content_hash("abc") == content_hash("abd"))
    bad.push_back({"content hash", "abc"});
  return bad;
}

// -- the cache directory's stores ---------------------------------------------------------------------------

// a decoded function's every part, as the comparison reads it
bool same_code(const Code& a, const Code& b, std::string& why) {
  auto fail = [&](const char* w) {
    why = w;
    return false;
  };
  if (a.start != b.start || a.end != b.end || a.code != b.code) return fail("range or bytes");
  if (a.relocated != b.relocated || a.complete != b.complete || a.cut != b.cut || a.resume != b.resume)
    return fail("flags");
  if (a.tables != b.tables) return fail("tables");
  if (a.insns.size() != b.insns.size() || a.field_list.size() != b.field_list.size()) return fail("counts");
  for (size_t i = 0; i < a.insns.size(); ++i) {
    const Lean &x = a.insns[i], &y = b.insns[i];
    if (x.off != y.off || x.field != y.field || x.size != y.size || x.nfields != y.nfields ||
        x.addressed != y.addressed || a.mnemonic(x).str() != b.mnemonic(y).str())
      return fail("instruction");
  }
  for (size_t i = 0; i < a.field_list.size(); ++i) {
    const Field &x = a.field_list[i], &y = b.field_list[i];
    if (x.value != y.value || x.access != y.access || x.off != y.off || x.size != y.size || x.kind != y.kind)
      return fail("field");
  }
  return true;
}

// a function with every kind of field: a call out of it, a RIP-relative load, a relocated 64-bit immediate, and an
// in-function switch table (mov eax, [rcx*4 + table]) that ends its code; then `n` small functions after it
struct StoreImage {
  Side s{0};
  u64 f = 0, f_end = 0, imm = 0;  // imm: where the relocated 64-bit immediate is
  std::vector<std::pair<u64, u64>> small;
  explicit StoreImage(int n) {
    u64 g = s.put(DATA, le32b(7));
    u64 callee = s.put(TEXT, unhex("c3"));
    f = BASE + ((s.cur[TEXT] + 15) & ~u64(15));
    Bytes code = call(f, callee) + mov_eax_g(f + 5, g);
    u64 imm_at = f + code.size() + 2;
    code += unhex("48b8") + le64b(g);            // mov rax, g (relocated)
    u64 table_rva = f - BASE + code.size() + 8;  // after the mov eax, [rcx*4 + table] and the ret
    code += unhex("8b048d") + le32b(u32(table_rva)) + unhex("c3");
    code += le32b(1) + le32b(2) + le32b(3);  // the table
    s.put(TEXT, code);
    s.relocs.push_back(imm_at);
    imm = imm_at;
    f_end = f + code.size();
    for (int i = 0; i < n; ++i) {
      u64 at = s.put(TEXT, unhex("b8") + le32b(u32(i)) + unhex("c3"));
      small.push_back({at, at + 6});
    }
  }
};

std::string self_path;

// the code store of StoreImage(22), written by this process with other mnemonics interned first (another run numbers
// them otherwise: the store names them by text)
int write_code_store(const std::string& path) {
  for (const char* m : {"zz-first", "zz-second", "zz-third"}) Mnem{m};
  StoreImage si(22);
  Image img = si.s.image();
  CodeStore st(path, img, "decoder 1");
  for (auto& [a, b] : si.small) st.code(a, b);
  st.code(si.f, si.f_end);
  st.save();
  return 0;
}

Problems code_store_case() {
  namespace fs = std::filesystem;
  Problems bad;
  fs::path d = fs::temp_directory_path() / ("verifier-code-" + unique_suffix());
  fs::create_directories(d);
  std::string path = (d / "code.bin").string();
  StoreImage si(22);
  Image img = si.s.image();
  auto check = [&](CodeStore& st, const Image& im, u64 a, u64 b, const char* what) {
    auto got = st.code(a, b);
    Code fresh(im, a, b);
    std::string why;
    if (!same_code(*got, fresh, why)) bad.push_back({"code store", std::string(what) + ": " + why});
  };
  {
    CodeStore st(path, img, "decoder 1");
    check(st, img, si.f, si.f_end, "decoded");
    for (auto& [a, b] : si.small) check(st, img, a, b, "decoded");
    if (st.stats().hits || st.stats().misses != 23) bad.push_back({"code store", "an empty store has hits"});
    st.save();
  }
  {
    CodeStore st(path, img, "decoder 1");
    check(st, img, si.f, si.f_end, "from the store");
    for (auto& [a, b] : si.small) check(st, img, a, b, "from the store");
    if (st.stats().hits != 23 || st.stats().misses)
      bad.push_back({"code store", "a stored function was decoded again"});
    Code fresh(img, si.f, si.f_end);
    if (fresh.field_list.size() < 4 || fresh.tables.empty())
      bad.push_back({"code store", "the test function lacks a field kind"});
  }
  {
    // written by another process, whose mnemonic ids differ from this one's
    std::string other = (d / "other.bin").string();
    std::string cmd = "\"" + self_path + "\" --write-code-store \"" + other + "\"";
#ifdef _WIN32
    cmd = "\"" + cmd + "\"";  // cmd /c drops the outer quotes of a line holding more than two
#endif
    if (std::system(cmd.c_str()) != 0 || !fs::exists(other)) {
      bad.push_back({"code store", "the second process wrote nothing"});
    } else {
      CodeStore st(other, img, "decoder 1");
      check(st, img, si.f, si.f_end, "from another process");
      for (auto& [a, b] : si.small) check(st, img, a, b, "from another process");
      if (st.stats().hits != 23) bad.push_back({"code store", "another process's functions not used"});
    }
  }
  {
    Side changed = si.s;
    changed.write(si.f + 7, le32b(0x40));  // the RIP-relative displacement
    Image img2 = changed.image();
    CodeStore st(path, img2, "decoder 1");
    check(st, img2, si.f, si.f_end, "bytes changed");
    if (st.stats().misses != 1) bad.push_back({"code store", "changed bytes taken from the store"});
    check(st, img2, si.small[0].first, si.small[0].second, "unchanged neighbour");
    if (st.stats().hits != 1) bad.push_back({"code store", "an unchanged function was not taken from the store"});
  }
  {
    Side changed = si.s;
    changed.relocs.clear();
    Image img2 = changed.image();
    CodeStore st(path, img2, "decoder 1");
    check(st, img2, si.f, si.f_end, "relocation gone");
    if (st.stats().misses != 1) bad.push_back({"code store", "changed relocations taken from the store"});
  }
  {
    CodeStore st(path, img, "decoder 2");
    check(st, img, si.f, si.f_end, "other decoder");
    if (st.stats().misses != 1) bad.push_back({"code store", "another decoder's functions used"});
  }
  {
    CodeStore st(path, img, "decoder 1");
    auto [a, b] = si.small[0];
    check(st, img, a + 1, b, "other range");  // the same bytes from another start: not the stored function
    if (st.stats().misses != 1) bad.push_back({"code store", "a function used for another range"});
  }
  // a run asking for every stored function and one it lacks decodes that one without rewriting the file; one that lacks
  // a twentieth of what it asks for rewrites it, and the next run finds them all
  std::string before = read_file(path);
  u64 extra = si.s.put(TEXT, unhex("b863000000c3"));
  Side more = si.s;
  Image img3 = more.image();
  {
    CodeStore st(path, img3, "decoder 1");
    check(st, img3, si.f, si.f_end, "stored");
    for (auto& [a, b] : si.small) check(st, img3, a, b, "stored");
    check(st, img3, extra, extra + 6, "new");
    st.save();
  }
  if (read_file(path) != before) bad.push_back({"code store", "rewritten for one missing function in 24"});
  {
    CodeStore st(path, img3, "decoder 1");
    check(st, img3, extra, extra + 6, "new");
    for (int i = 0; i < 2; ++i) check(st, img3, si.small[size_t(i)].first + 1, si.small[size_t(i)].second, "new");
    st.save();
  }
  {
    CodeStore st(path, img3, "decoder 1");
    check(st, img3, extra, extra + 6, "kept");
    check(st, img3, si.f, si.f_end, "kept");
    if (st.stats().hits != 2 || st.stats().misses) bad.push_back({"code store", "a rewrite lost functions"});
  }
  fs::remove_all(d);
  return bad;
}

Problems diff_store_case() {
  namespace fs = std::filesystem;
  Problems bad;
  fs::path d = fs::temp_directory_path() / ("verifier-diffs-" + unique_suffix());
  fs::create_directories(d);
  std::string path = (d / "diffs.bin").string();
  StoreImage o(0);
  Side changed = o.s;
  changed.write(o.imm, le64b(0x180009999));  // the 64-bit immediate: another value
  Side retargeted = o.s;
  retargeted.write(o.f + 1, le32b(u32(i32(0x40))));  // the call: the same instructions and offsets, another callee
  Side reordered = o.s;
  reordered.write(o.f + 5, unhex("90909090909090909090909090909090"));
  Image io = o.s.image(), ir = changed.image(), ir2 = reordered.image(), ir3 = retargeted.image();
  auto by_va = [](u64 t) { return Key::of_va(t); };
  auto toks = [&](const Image& im) { return symbolise(Code(im, o.f, o.f_end), by_va, false); };
  auto offs = [&](const Image& im) {
    std::vector<u32> v;
    Code c(im, o.f, o.f_end);
    for (auto& l : c.insns) v.push_back(l.off);
    return v;
  };
  NameOf names = [&](u64 va) { return va == o.f ? std::string_view("f") : std::string_view(); };
  Toks ot = toks(io), rt = toks(ir), rt2 = toks(ir2), rt3 = toks(ir3);
  auto want = [&](const Toks& r, const Image& im) {
    return DiffStore::Entry{classify(ot, r), insn_diff(offs(io), offs(im), ot, r, names)};
  };
  auto same = [](const DiffStore::Entry& a, const DiffStore::Entry& b) {
    return a.category == b.category && a.diff == b.diff;
  };
  {
    DiffStore st(path, "key 1");
    if (!same(st.get(offs(io), offs(ir), ot, rt, names), want(rt, ir))) bad.push_back({"diff store", "made"});
    if (st.stats().misses != 1) bad.push_back({"diff store", "an empty store has hits"});
    st.save();
  }
  {
    DiffStore st(path, "key 1");
    if (!same(st.get(offs(io), offs(ir), ot, rt, names), want(rt, ir))) bad.push_back({"diff store", "from the store"});
    if (st.stats().hits != 1) bad.push_back({"diff store", "a stored diff was made again"});
    if (!same(st.get(offs(io), offs(ir2), ot, rt2, names), want(rt2, ir2)))
      bad.push_back({"diff store", "other tokens"});
    if (st.stats().misses != 1) bad.push_back({"diff store", "other tokens taken from the store"});
    if (offs(ir3) != offs(io) || !same(st.get(offs(io), offs(ir3), ot, rt3, names), want(rt3, ir3)))
      bad.push_back({"diff store", "other targets at the same offsets"});
    // the unchanged function against itself differs from each stored case in one field only: the immediate's value
    // (changed) or the call's target (retargeted); a key leaving either out would find that case's diff
    if (!same(st.get(offs(io), offs(io), ot, ot, names), want(ot, io)))
      bad.push_back({"diff store", "one field apart"});
    // the same tokens but for the name the call's target resolves to
    auto named = [&](const char* n) {
      Toks t = ot;
      t[0].ops[0].key = Key::named(Key::UNRESOLVED, n);
      return t;
    };
    Toks na = named("alpha"), nb = named("beta");
    st.get(offs(io), offs(io), ot, na, names);
    if (!same(st.get(offs(io), offs(io), ot, nb, names),
              DiffStore::Entry{classify(ot, nb), insn_diff(offs(io), offs(io), ot, nb, names)}))
      bad.push_back({"diff store", "another name"});
    st.save();
  }
  {
    DiffStore st(path, "key 2");
    st.get(offs(io), offs(ir), ot, rt, names);
    if (st.stats().misses != 1) bad.push_back({"diff store", "another key's diffs used"});
  }
  {
    DiffStore st(path, "key 1");
    st.get(offs(io), offs(ir), ot, rt, names);
    st.get(offs(io), offs(ir2), ot, rt2, names);
    if (st.stats().hits != 2) bad.push_back({"diff store", "a rewrite lost diffs"});
  }
  fs::remove_all(d);
  return bad;
}

Problems source_cache_case() {
  namespace fs = std::filesystem;
  Problems bad;
  fs::path d = fs::temp_directory_path() / ("verifier-sources-" + unique_suffix());
  fs::create_directories(d / "src");
  std::string cache = (d / "sources.bin").string(), root = (d / "src").string();
  auto write = [&](const std::string& name, const std::string& text, int age_s) {
    fs::path f = d / "src" / name;
    std::ofstream(f, std::ios::binary) << text;
    fs::last_write_time(f, fs::file_time_type::clock::now() - std::chrono::seconds(age_s));
  };
  write("a.cpp", "// FUNCTION: MOD 0x1000\nint f(int x) { return x; }\n// GLOBAL: MOD 0x2000\n\n", 3600);
  write("b.h", "// VTABLE: MOD 0x3000 FOLDED\nclass C {\n// STUB: MOD 0x4000 (int)\nvoid g(int);\n", 3600);
  write("notes.txt", "no annotations\n", 3600);
  struct Run {
    std::vector<Annotation> anns;
    std::vector<Ignored> ign;
    std::map<std::string, std::string> hashes;
  };
  auto same = [](const Run& a, const Run& b) {
    if (a.anns.size() != b.anns.size() || a.ign.size() != b.ign.size() || a.hashes != b.hashes) return false;
    for (size_t i = 0; i < a.anns.size(); ++i) {
      const Annotation &x = a.anns[i], &y = b.anns[i];
      if (x.kind != y.kind || x.va != y.va || x.name != y.name || x.flags.folded != y.flags.folded ||
          x.flags.dtor != y.flags.dtor || x.flags.sig != y.flags.sig || x.path != y.path || x.line != y.line)
        return false;
    }
    for (size_t i = 0; i < a.ign.size(); ++i)
      if (a.ign[i].path != b.ign[i].path || a.ign[i].line != b.ign[i].line || a.ign[i].text != b.ign[i].text)
        return false;
    return true;
  };
  auto uncached = [&] {
    Run r;
    r.anns = parse_annotations({root}, "MOD", &r.ign, [&](const ListedFile& f, std::string_view data) {
      r.hashes[f.path] = content_hash(data);
    });
    return r;
  };
  auto cached = [&](const std::string& key, SourceCache::Stats& stats) {
    Run r;
    SourceCache c(cache, key, two_seconds_ago());
    r.anns = parse_annotations({root}, "MOD", &r.ign, nullptr, &c,
                               [&](const ListedFile& f, const std::string& h) { r.hashes[f.path] = h; });
    c.save();
    stats = c.stats();
    return r;
  };
  SourceCache::Stats st;
  if (!same(cached("key", st), uncached()) || st.hits) bad.push_back({"sources cache", "first run"});
  if (!same(cached("key", st), uncached()) || st.hits != 3 || st.misses)
    bad.push_back({"sources cache", "unchanged files read again"});
  write("a.cpp",
        "// FUNCTION: MOD 0x1000\nint f(int x) { return x; }\n// FUNCTION: MOD 0x1100\nint h() { return 1; }\n", 1800);
  if (!same(cached("key", st), uncached()) || st.hits != 2 || st.misses != 1)
    bad.push_back({"sources cache", "an edited file"});
  // an edit within one tick of the file clock leaves the size and time as they were: a file that recent is read again
  write("b.h", "// VTABLE: MOD 0x3000 FOLDED\nclass C {\n// STUB: MOD 0x4000 (int)\nvoid g(int);\n", 0);
  auto t = fs::last_write_time(d / "src" / "b.h");
  cached("key", st);
  write("b.h", "// VTABLE: MOD 0x3008 FOLDED\nclass C {\n// STUB: MOD 0x4008 (int)\nvoid g(int);\n", 0);
  fs::last_write_time(d / "src" / "b.h", t);
  if (!same(cached("key", st), uncached()) || st.misses != 1)
    bad.push_back({"sources cache", "a file written within two seconds"});
  if (!same(cached("other key", st), uncached()) || st.hits)
    bad.push_back({"sources cache", "another key's entries used"});
  fs::remove_all(d);
  return bad;
}

Problems replay_record() {
  namespace fs = std::filesystem;
  Problems bad;
  fs::path d = fs::temp_directory_path() / ("verifier-last-" + unique_suffix());
  fs::create_directories(d);
  std::string path = (d / "last.txt").string();
  std::string stamps(300, 's'), out = "MATCH 0x1000\n", report = content_hash("{\n  \"results\": []\n}\n");
  auto never = [] { return std::string("not asked for"); };
  bool asked = false;
  auto is = [&](std::string v) {
    return [&asked, v] {
      asked = true;
      return v;
    };
  };
  save_last(path, "command", "image stamp", stamps, "image hash", "key", out, report, 1);
  Last l;
  // the stamps as given: a run with the same ones replays by them, without hashing the image or the inputs
  if (!load_last(
          path, "command", "image stamp", [&] { return stamps; }, is("other"), is("other"), l) ||
      !l.by_stamps || asked)
    bad.push_back({"replay", "the same stamps do not replay by themselves"});
  if (l.out != out || l.report_hash != report || l.rc != 1)
    bad.push_back({"replay", "the output, report hash or status differs"});
  // other stamps: the image's hash and the key decide
  asked = false;
  if (!load_last(
          path, "command", "image stamp", [] { return std::string("other stamps"); }, is("image hash"), is("key"), l) ||
      l.by_stamps || !asked)
    bad.push_back({"replay", "stale stamps with the same contents do not replay by the contents"});
  if (load_last(
          path, "command", "image stamp", [] { return std::string("other stamps"); }, is("other image"), never, l))
    bad.push_back({"replay", "another image replays"});
  if (load_last(path, "another command", "image stamp", [&] { return stamps; }, never, never, l))
    bad.push_back({"replay", "another command replays"});
  // no stamps (an input changed within two seconds): only the contents decide
  save_last(path, "command", "image stamp", "", "image hash", "key", out, "", 0);
  if (!load_last(
          path, "command", "image stamp", [] { return std::string(); }, is("image hash"), is("key"), l) ||
      l.by_stamps)
    bad.push_back({"replay", "a record without stamps does not replay by the contents"});
  if (!l.report_hash.empty()) bad.push_back({"replay", "a run without a report recorded one"});
  fs::remove_all(d);
  return bad;
}

Problems stamp_keys() {
  namespace fs = std::filesystem;
  fs::path d = fs::temp_directory_path() / ("verifier-stamps-" + unique_suffix());
  fs::create_directories(d / "src" / "sub");
  Problems bad;
  auto write = [](const fs::path& path, const std::string& text) { std::ofstream(path, std::ios::binary) << text; };
  auto old = fs::file_time_type::clock::now() - std::chrono::hours(1);
  std::vector<fs::path> files{
      d / "x.dll", d / "x.map", d / "matched.txt", d / "src" / "a.cpp", d / "src" / "sub" / "b.h", d / "verifier.exe"};
  for (auto& f : files) {
    write(f, "1");
    fs::last_write_time(f, old);
  }
  write(d / "verifier.conf", "a = 1");
  Args a;
  a.rebuilt = files[0].string();
  a.map = files[1].string();
  a.matched = files[2].string();
  a.src = {(d / "src").string()};
  Config p;
  p.file = (d / "verifier.conf").string();  // by its contents: young or not
  std::vector<std::string> args{"--check"};
  std::string exe = files[5].string();
  std::string key = stamp_key(a, p, exe);
  if (key.empty() || stamp_key(a, p, exe) != key) bad.push_back({"stamps", "no key, or another for the same inputs"});
  fs::last_write_time(files[4], old + std::chrono::seconds(1));
  std::string touched = stamp_key(a, p, exe);
  if (touched == key || touched.empty()) bad.push_back({"stamps", "a source's time ignored"});
  write(files[1], "22");
  fs::last_write_time(files[1], old);
  if (stamp_key(a, p, exe) == touched) bad.push_back({"stamps", "the map's size ignored"});
  write(files[3], "1");  // young: the stamps cannot tell a change within its clock tick
  if (!stamp_key(a, p, exe).empty()) bad.push_back({"stamps", "a key while a source is young"});
  fs::last_write_time(files[3], old);
  write(files[0], "1");
  if (!stamp_key(a, p, exe).empty()) bad.push_back({"stamps", "a key while the rebuilt image is young"});
  std::error_code ec;
  fs::remove_all(d, ec);
  return bad;
}

// a file's contents read (below 1 MB) or mapped, each the bytes written; absent files and directories are absent
Problems file_contents() {
  namespace fs = std::filesystem;
  fs::path d = fs::temp_directory_path() / ("verifier-files-" + unique_suffix());
  fs::create_directories(d / "dir");
  Problems bad;
  for (size_t n : {size_t(0), size_t(1), size_t(4097), (size_t(1) << 20) - 1, size_t(1) << 20, (size_t(3) << 20) + 5}) {
    Bytes data(n, '\0');
    for (size_t i = 0; i < n; ++i) data[i] = char(i * 31 + (i >> 11));
    std::string path = (d / ("f" + std::to_string(n))).string();
    std::ofstream(path, std::ios::binary) << data;
    Bytes got;
    bool present = with_contents_if_present(path, [&](std::string_view v) { got = Bytes(v); });
    if (!present || got != data) bad.push_back({"files", "contents of " + std::to_string(n) + " bytes"});
    if (sha256_file_if_present(path) != sha256_hex(data) || sha256_file(path) != sha256_hex(data))
      bad.push_back({"files", "hash of " + std::to_string(n) + " bytes"});
  }
  for (auto& p : {d / "absent", d / "dir"}) {
    bool called = false;
    if (with_contents_if_present(p.string(), [&](std::string_view) { called = true; }) || called ||
        sha256_file_if_present(p.string()) != "")
      bad.push_back({"files", p.filename().string() + " is present"});
    bool threw = false;
    try {
      with_contents(p.string(), [](std::string_view) {});
    } catch (const std::runtime_error&) { threw = true; }
    if (!threw) bad.push_back({"files", "with_contents of " + p.filename().string() + " does not throw"});
  }
  std::error_code ec;
  fs::remove_all(d, ec);
  return bad;
}

// unit check: line splitting (\n, \r\n, \r), in memory and streamed in blocks
// the name table against a std::map, through many growths: a value set again keeps its place
Problems name_table() {
  std::map<std::string, u64> want;
  std::vector<std::string> names;
  for (int i = 0; i < 20000; ++i) names.push_back("?name" + std::to_string(i * 7919 % 20000) + "@@");
  Problems bad;
  // growing from empty, reserved for all, and reserved for too few
  for (size_t reserved : {size_t(0), names.size(), size_t(100)}) {
    NameTable t;
    t.reserve(reserved);
    want.clear();
    for (size_t i = 0; i < names.size(); ++i) {
      t.set(names[i], i);
      want[names[i]] = i;
    }
    for (size_t i = 0; i < names.size(); i += 3) {
      t.set(names[i], i + 1);
      want[names[i]] = i + 1;
    }
    std::string at = " (reserved " + std::to_string(reserved) + ")";
    if (t.size() != want.size()) bad.push_back({"names", "size " + std::to_string(t.size()) + at});
    for (auto& [n, v] : want)
      if (const u64* got = t.find(n); !got || *got != v) {
        bad.push_back({"names", "lookup " + n + at});
        break;
      }
    if (t.find("?absent@@") || t.contains("")) bad.push_back({"names", "found a name never set" + at});
    size_t k = 0;
    for (auto& [n, v] : t)
      if (n != names[k++]) {
        bad.push_back({"names", "order at " + std::to_string(k - 1) + at});
        break;
      }
    // restored from its entries and index (a snapshot): it answers as the table it was taken from
    NameTable r;
    if (!r.restore(std::vector<NameTable::Entry>(t.begin(), t.end()), t.index())) {
      bad.push_back({"names", "a table's own index not restored" + at});
    } else {
      for (auto& [n, v] : want)
        if (const u64* got = r.find(n); !got || *got != v) {
          bad.push_back({"names", "restored lookup " + n + at});
          break;
        }
      if (r.find("?absent@@")) bad.push_back({"names", "a restored table finds a name never set" + at});
    }
  }
  // an index that does not fit its entries is refused
  {
    NameTable t, r;
    for (size_t i = 0; i < 100; ++i) t.set(names[i], i);
    std::vector<NameTable::Entry> e(t.begin(), t.end());
    std::vector<u32> wrong = t.index();
    wrong[0] = u32(e.size() + 1);
    std::vector<u32> few(e.size(), 0);
    if (r.restore(e, wrong) || r.restore(e, few) ||
        r.restore(std::vector<NameTable::Entry>(e.begin(), e.begin() + 50), t.index()))
      bad.push_back({"names", "an index that does not fit restored"});
  }
  // the function table: in order or not, of several at one address the last
  FunctionTable sorted, shuffled;
  std::vector<IdaFunction> in_order, mixed;
  for (u64 i = 0; i < 100; ++i) in_order.push_back({0x1000 + 16 * i, 16, "f", false, false});
  mixed = {in_order[5], in_order[2], in_order[9], in_order[2]};
  mixed.back().size = 99;
  sorted.assign(in_order);
  shuffled.assign(mixed);
  if (sorted.size() != 100 || !sorted.contains(0x1000 + 16 * 99) || sorted.begin()->ea != 0x1000)
    bad.push_back({"functions", "a table in order"});
  if (shuffled.size() != 3 || shuffled.begin()->ea != in_order[2].ea || shuffled.at(in_order[2].ea).size != 99 ||
      (shuffled.begin() + 2)->ea != in_order[9].ea)
    bad.push_back({"functions", "a table out of order, with two at one address"});
  return bad;
}

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
  if (got2 != want2 || got3 != want2)
    bad.push_back({"lines", "streamed " + std::to_string(got2.size()) + " vs " + std::to_string(want2.size())});
  return bad;
}

}  // namespace

int main(int argc, char** argv) {
  self_path = argv[0];
  // a second process writes a code store: its mnemonics numbered otherwise than the tests' (see code_store_case)
  if (argc == 3 && std::string(argv[1]) == "--write-code-store") return write_code_store(argv[2]);
  std::string path = VERIFIER_FIXTURES;
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "-v")
      verbose = true;
    else
      path = a;
  }
  Value doc = json::parse(read_file(path));
  data_cases(doc);
  struct Hand {
    const char* name;
    const char* want;
    std::function<Problems()> fn;
  };
  std::vector<Hand> hand = {
      {"category: other branch target", "reference", [] { return category(0, 0x180001b00, true); }},
      {"category: other immediate", "immediate", [] { return category(1, 0, false); }},
      {"build hashes pair one-to-one", nullptr, build_hashes},
      {"qualified names", nullptr, qualified_names},
      {"definition names", nullptr, definition_names},
      {"long names", nullptr, long_names},
      {"name cache file", nullptr, name_cache},
      {"report writer", nullptr, report_writer},
      {"destructor pairing", nullptr, destructor_pairing},
      {"folded annotations", nullptr, folded_annotations},
      {"instruction diff", nullptr, instruction_diff},
      {"linear matcher", nullptr, [&] { return linear_matcher(doc); }},
      {"leaf extent", nullptr, leaf_extent_case},
      {"decode at two addresses", nullptr, decode_case},
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
      {"unit: content hash", nullptr, content_hashes},
      {"unit: code store", nullptr, code_store_case},
      {"unit: diff store", nullptr, diff_store_case},
      {"unit: sources cache", nullptr, source_cache_case},
      {"unit: replay record", nullptr, replay_record},
      {"unit: file contents", nullptr, file_contents},
      {"unit: stamp key", nullptr, stamp_keys},
      {"unit: line splitting", nullptr, line_splitting},
      {"unit: name table", nullptr, name_table},
      {"unit: PE file layout", nullptr, file_layout},
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
    if (!written.count(o.as_str())) {
      ++failures;
      std::printf("BAD %s: listed under \"other\" but not written out\n", o.as_str().c_str());
    }
  std::printf("%zu cases, %d failures\n", doc["cases"].arr.size() + hand.size(), failures);
  return failures;
}
