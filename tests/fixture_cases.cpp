// The data-driven comparison cases of tests/data/fixtures.json, each replayed through a Comparer
// whose hooks answer from the case's mapping.
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
Findings replay(const Value& c) {
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
    Findings probs, expected;
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

}  // namespace

void run_fixture_cases(const json::Value& doc) { data_cases(doc); }

}  // namespace verifier::test
