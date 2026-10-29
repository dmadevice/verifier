// compare_reports A.json B.json: the two verifier reports field by field. Results pair by (orig, src); a
// difference in an acceptance field (status, category, problems, unresolved), a result only one report has,
// or a different summary total exits 1. Other fields (name, sizes, overloads, first_diff, diff) are listed
// and only fail with --strict.
#include <cstdio>
#include <map>
#include <set>
#include <string>

#include "json.hpp"
#include "util.hpp"

using namespace verifier;
using json::Value;

namespace {

std::string show(const Value* v) {
  if (!v) return "(absent)";
  std::string s = json::dump(*v);
  for (auto& c : s) if (c == '\n') c = ' ';
  return s.size() > 300 ? s.substr(0, 300) + "..." : s;
}

// equal values; objects compare by key, whatever their order
bool equal(const Value& a, const Value& b) {
  if (a.type != b.type) return false;
  switch (a.type) {
    case Value::Array:
      if (a.arr.size() != b.arr.size()) return false;
      for (size_t i = 0; i < a.arr.size(); ++i) if (!equal(a.arr[i], b.arr[i])) return false;
      return true;
    case Value::Object:
      if (a.obj.size() != b.obj.size()) return false;
      for (auto& [k, v] : a.obj) {
        const Value* w = b.get(k);
        if (!w || !equal(v, *w)) return false;
      }
      return true;
    default:
      return json::dump(a) == json::dump(b);
  }
}

bool same(const Value* a, const Value* b) {
  if (!a || !b) return a == b;
  return equal(*a, *b);
}

}  // namespace

int main(int argc, char** argv) {
  bool strict = false;
  std::vector<std::string> files;
  for (int i = 1; i < argc; ++i) {
    std::string s = argv[i];
    if (s == "--strict") strict = true;
    else files.push_back(s);
  }
  if (files.size() != 2) {
    std::fprintf(stderr, "usage: compare_reports [--strict] A.json B.json\n");
    return 2;
  }
  Value a = json::parse(read_file(files[0])), b = json::parse(read_file(files[1]));
  auto index = [](const Value& doc) {
    std::map<std::string, const Value*> m;
    for (auto& r : doc["results"].arr) m[r["orig"].s + " " + r["src"].s] = &r;
    return m;
  };
  auto ia = index(a), ib = index(b);
  static const char* ACCEPT[] = {"status", "category", "problems", "unresolved"};
  size_t accept = 0, other = 0;
  std::set<std::string> keys;
  for (auto& [k, v] : ia) keys.insert(k);
  for (auto& [k, v] : ib) keys.insert(k);
  for (auto& k : keys) {
    auto x = ia.find(k), y = ib.find(k);
    if (x == ia.end() || y == ib.end()) {
      std::printf("%s: only in %s\n", k.c_str(), x == ia.end() ? files[1].c_str() : files[0].c_str());
      ++accept;
      continue;
    }
    std::set<std::string> fields;
    for (auto& [f, v] : x->second->obj) fields.insert(f);
    for (auto& [f, v] : y->second->obj) fields.insert(f);
    for (auto& f : fields) {
      const Value *p = x->second->get(f), *q = y->second->get(f);
      if (same(p, q)) continue;
      bool acc = false;
      for (auto* af : ACCEPT) acc |= f == af;
      (acc ? accept : other)++;
      std::printf("%s %s%s:\n  < %s\n  > %s\n", k.c_str(), f.c_str(), acc ? "" : " (not an acceptance field)", show(p).c_str(),
                  show(q).c_str());
    }
  }
  for (auto& [f, v] : a.obj) {
    if (f == "results") continue;
    if (!same(&v, b.get(f))) {
      ++accept;
      std::printf("summary %s:\n  < %s\n  > %s\n", f.c_str(), show(&v).c_str(), show(b.get(f)).c_str());
    }
  }
  for (auto& [f, v] : b.obj)
    if (!a.get(f)) { ++accept; std::printf("summary %s: only in %s\n", f.c_str(), files[1].c_str()); }
  std::printf("%zu results compared: %zu acceptance differences, %zu other differences\n", keys.size(), accept, other);
  return accept || (strict && other) ? 1 : 0;
}
