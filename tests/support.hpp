// What the test files share: the harness (a case is a name, the category it must report or none for a MATCH, and a
// function giving the problems found), synthetic PE images to compare, and fakes of the rebuild and of a run.
#pragma once
#include <algorithm>
#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "annotations.hpp"
#include "compare.hpp"
#include "inputs.hpp"
#include "json.hpp"
#include "name_cache.hpp"
#include "names.hpp"
#include "pairing.hpp"
#include "report.hpp"
#include "result.hpp"
#include "sha256.hpp"
#include "verify.hpp"

namespace verifier::test {

using json::Value;

// -- the harness ---------------------------------------------------------------------------------------------

// what a case found: a comparison's problems (their categories by name), or a check's own failures
struct Finding {
  std::string category, detail;
  bool operator==(const Finding&) const = default;
};
struct Findings : std::vector<Finding> {
  using std::vector<Finding>::vector;
  Findings(const Problems& ps) {
    for (auto& p : ps) push_back({std::string(category_name(p.category)), p.detail});
  }
};

struct Case {
  std::string name;
  const char* want;  // the category the problems must include; nullptr: no problems (a MATCH)
  std::function<Findings()> fn;
};
using Cases = std::vector<Case>;

const Value& fixtures();         // tests/data/fixtures.json, read once

// each test file's cases (main runs them in this order)
void add_names_cases(Cases&);
void add_report_cases(Cases&);
void add_compare_cases(Cases&);
void add_eh_cases(Cases&);
void add_pairing_cases(Cases&);
void add_inputs_cases(Cases&);
void add_cache_cases(Cases&);
void add_util_cases(Cases&);
void run_fixture_cases(const Value& doc);  // reported as they run
void report(const std::string& name, const char* want, const Findings& probs, bool ok, std::string note = "");
bool verdict(const char* want, const Findings& probs);

inline Findings bad_if(bool bad, const std::string& cat, const std::string& why) {
  return bad ? Findings{{cat, why}} : Findings{};
}

// a name for temporary files no other run uses at the same time
inline std::string unique_suffix() {
  static int n = 0;
  return std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + "-" + std::to_string(++n);
}

// -- names and symbols ---------------------------------------------------------------------------------------

using NameMap = std::unordered_map<u64, std::string_view>;
inline Symbols symbols_at(std::vector<u64> vas) {  // a symbol with an empty name at each address, in address order
  std::sort(vas.begin(), vas.end());
  std::vector<std::pair<u64, std::string_view>> syms;
  for (u64 v : vas) syms.emplace_back(v, "");
  return Symbols(syms);
}
inline NameOf name_of(const NameMap& m) {  // a lookup in m ("" for none)
  return [&m](u64 va) {
    auto it = m.find(va);
    return it == m.end() ? std::string_view() : it->second;
  };
}

// -- synthetic images ----------------------------------------------------------------------------------------

constexpr u64 BASE = 0x180000000;
constexpr u64 TEXT = 0x1000, RDATA = 0x3000, DATA = 0x5000, END = 0x7000;

inline std::vector<Section> sections() {
  return {{BASE + TEXT, BASE + RDATA, 0x60000020},
          {BASE + RDATA, BASE + DATA, 0x40000040},
          {BASE + DATA, BASE + END, 0xC0000040}};
}

inline Bytes le32b(u32 v) { return Bytes(reinterpret_cast<const char*>(&v), 4); }
inline Bytes le64b(u64 v) { return Bytes(reinterpret_cast<const char*>(&v), 8); }
inline Bytes unhex(const std::string& h) {
  Bytes out;
  for (size_t i = 0; i + 1 < h.size(); i += 2) out.push_back(char(std::stoi(h.substr(i, 2), nullptr, 16)));
  return out;
}

// one side's image being written: each section filled from its start (shifted by `shift` on the rebuilt side)
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

inline Bytes rip(u64 at, const Bytes& opcode, u64 target, u64 size, const Bytes& tail = "") {
  return opcode + le32b(u32(i32(i64(target) - i64(at + size)))) + tail;
}
inline Bytes call(u64 at, u64 target) { return "\xe8" + le32b(u32(i32(i64(target) - i64(at + 5)))); }
inline Bytes lea_rcx(u64 at, u64 t) { return rip(at, "\x48\x8d\x0d", t, 7); }
inline Bytes mov_eax_g(u64 at, u64 t) { return rip(at, Bytes("\x8b\x05", 2), t, 6); }

inline u32 unwind_info(Side& s) {
  Bytes body{char(1), 4, 1, 0, 4, 0x42, 0, 0};
  return u32(s.put(RDATA, body, 4) - BASE);
}

// -- tokens --------------------------------------------------------------------------------------------------

inline Op opm(const char* base, i64 disp, int size) {
  Op o{};
  o.k = Op::M;
  o.base = reg_named(base);
  o.scale = 1;
  o.v = disp;
  o.size = u16(size);
  return o;
}
inline Op opi(i64 v) {
  Op o{};
  o.k = Op::I;
  o.v = v;
  return o;
}
inline Op opsym(Key k) {
  Op o{};
  o.k = Op::SYM;
  o.key = std::move(k);
  return o;
}
inline Op opr(const char* r) {
  Op o{};
  o.k = Op::R;
  o.base = reg_named(r);
  return o;
}
inline Op oprel(i64 v) {
  Op o{};
  o.k = Op::REL;
  o.v = v;
  return o;
}

// -- fakes ---------------------------------------------------------------------------------------------------

inline Lookup fixed_lookup(const std::map<std::string, u64>& m, const std::string& key) {
  return {{m.at(key)}, key, 1};
}

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

// a Pairing over fake Original/Rebuilt with real hooks
struct FakeRun {
  Image O, R;
  Original orig;
  FakeRebuilt reb;
  std::unique_ptr<Pairing> p;
  std::unique_ptr<CodeCache> oc, rc;
  std::unique_ptr<Comparer> cmp;
  Comparer* c = nullptr;
  void start(const std::vector<Annotation>& anns) {
    orig.img = O;
    reb.img = R;
    p = std::make_unique<Pairing>(orig, reb, anns);
    oc = std::make_unique<CodeCache>(&orig.img);
    rc = std::make_unique<CodeCache>(&reb.img);
    p->use_caches(*oc, *rc);
    cmp = std::make_unique<Comparer>(
        &orig.img, &reb.img, [this](u64 t) { return p->resolve(t); }, &orig.vtables,
        [this](u64 va) { return orig.ida_name(va); }, p.get());
    c = cmp.get();
    p->prebind(c->m);
  }
};

}  // namespace verifier::test
