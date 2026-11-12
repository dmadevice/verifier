// fixture-dump: a case of tests/data/fixtures.json printed readably.
//   fixture-dump [fixtures.json] [NAME-OR-INDEX...]      (no names: list the cases)
// For each case: what it wants, the problems it must report, both sides' compared functions disassembled, the other
// bytes each side holds (by section), relocations, .pdata and imports, and the mapping the comparer's hooks answer.
#include <cstdio>
#include <string>
#include <vector>

#include "json.hpp"
#include "util.hpp"
#include "x64.hpp"

#ifndef VERIFIER_FIXTURES
#define VERIFIER_FIXTURES "tests/data/fixtures.json"
#endif

using namespace verifier;
using json::Value;

namespace {

constexpr u64 BASE = 0x180000000;  // as the cases' images are laid out (tests/support.hpp)

Bytes unhex(const std::string& h) {
  Bytes out;
  for (size_t i = 0; i + 1 < h.size(); i += 2) out.push_back(char(std::stoi(h.substr(i, 2), nullptr, 16)));
  return out;
}

const char* section_of(u64 off) {
  return off < 0x1000 ? "headers" : off < 0x3000 ? ".text" : off < 0x5000 ? ".rdata" : ".data";
}

// a value on one line, addresses in hex
std::string compact(const Value& v) {
  if (v.type == Value::Int) return v.i >= 0x1000 ? hex(u64(v.i)) : std::to_string(v.i);
  if (v.type == Value::Array) {
    std::vector<std::string> parts;
    for (auto& x : v.arr) parts.push_back(compact(x));
    return "[" + join(parts, ", ") + "]";
  }
  if (v.type == Value::Null) return "null";
  if (v.type == Value::String) return v.s;
  return json::dump(v);
}

std::string va_list(const Value& arr) {
  std::vector<std::string> v;
  for (auto& x : arr.arr) v.push_back(compact(x));
  return join(v, " ");
}

void side(const char* title, const Value& s, const Value& fn) {
  u64 lo = u64(fn.arr[0].as_int()), hi = u64(fn.arr[1].as_int());
  std::printf("  %s: function %s..%s\n", title, hex(lo).c_str(), hex(hi).c_str());
  for (auto& c : s["mem"].arr) {
    u64 off = u64(c.arr[0].as_int());
    Bytes b = unhex(c.arr[1].as_str());
    u64 va = BASE + off;
    bool code = va <= lo && lo < va + b.size();
    if (code) {
      // the function's instructions, then what follows it in the chunk as bytes
      size_t start = size_t(lo - va), end = std::min(b.size(), size_t(hi - va));
      for (auto& ins : decode_linear(std::string_view(b).substr(start, end - start), lo))
        std::printf("    %s  %-24s %s\n", hex(ins.address).c_str(),
                    hex_bytes(std::string_view(b).substr(size_t(ins.address - va), ins.size)).c_str(),
                    ins.text().c_str());
      std::string_view rest = rstrip_char(std::string_view(b).substr(end), '\xcc');
      if (!rest.empty()) std::printf("    %s  after: %s\n", hex(hi).c_str(), hex_bytes(rest.substr(0, 64)).c_str());
    } else {
      std::string_view all = rstrip_char(b, '\xcc');
      std::printf("    %s %-7s %s%s\n", hex(va).c_str(), section_of(off), hex_bytes(all.substr(0, 64)).c_str(),
                  all.size() > 64 ? " ..." : "");
    }
  }
  if (!s["relocs"].arr.empty()) std::printf("    relocations: %s\n", va_list(s["relocs"]).c_str());
  for (auto& p : s["pdata"].arr)
    std::printf("    .pdata %s..%s unwind rva %s\n", hex(u64(p.arr[0].as_int())).c_str(),
                hex(u64(p.arr[1].as_int())).c_str(), hex(u64(p.arr[2].as_int())).c_str());
  for (auto& i : s["imports"].arr)
    std::printf("    import %s: %s!%s\n", hex(u64(i.arr[0].as_int())).c_str(), i.arr[1].as_str().c_str(),
                i.arr[2].is_null() ? ("#" + std::to_string(i.arr[3].as_int())).c_str() : i.arr[2].as_str().c_str());
}

void dump(const Value& c, size_t index) {
  std::printf("[%zu] %s\n  want: %s\n", index, c["name"].as_str().c_str(),
              c["want"].is_null() ? "MATCH" : c["want"].as_str().c_str());
  for (auto& p : c["problems"].arr)
    std::printf("  problem %s: %s\n", p.arr[0].as_str().c_str(), p.arr[1].as_str().c_str());
  side("original", c["orig"], c["ofn"]);
  side("rebuilt", c["rebuilt"], c["rfn"]);
  const Value& m = c["mapping"];
  for (auto& k : m["keys"].arr) {
    std::string what =
        k.arr[1].as_str() == "va" ? hex(u64(k.arr[2].as_int())) : k.arr[1].as_str() + " " + k.arr[2].as_str();
    std::printf("  rebuilt %s stands for %s\n", hex(u64(k.arr[0].as_int())).c_str(), what.c_str());
  }
  for (auto& [name, v] : m.obj) {
    if (name == "keys" || (v.type == Value::Array && v.arr.empty())) continue;
    std::printf("  %s: %s\n", name.c_str(), compact(v).c_str());
  }
  for (auto& v : c["vtables"].arr)
    std::printf("  original vtable %s: slots %s\n", hex(u64(v.arr[0].as_int())).c_str(), va_list(v.arr[1]).c_str());
  for (auto& n : c["names"].arr)
    std::printf("  original name %s: %s\n", hex(u64(n.arr[0].as_int())).c_str(), n.arr[1].as_str().c_str());
  std::printf("\n");
}

}  // namespace

int main(int argc, char** argv) {
  std::string path = VERIFIER_FIXTURES;
  std::vector<std::string> wanted;
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if (a.size() > 5 && a.substr(a.size() - 5) == ".json")
      path = a;
    else
      wanted.push_back(a);
  }
  Value doc = json::parse(read_file(path));
  auto& cases = doc["cases"].arr;
  if (wanted.empty()) {
    for (size_t i = 0; i < cases.size(); ++i)
      std::printf("%3zu %-10s %s\n", i, cases[i]["want"].is_null() ? "MATCH" : cases[i]["want"].as_str().c_str(),
                  cases[i]["name"].as_str().c_str());
    return 0;
  }
  int missing = 0;
  for (auto& w : wanted) {
    bool found = false;
    for (size_t i = 0; i < cases.size(); ++i)
      if (cases[i]["name"].as_str() == w || std::to_string(i) == w) {
        dump(cases[i], i);
        found = true;
      }
    if (!found) {
      std::fprintf(stderr, "fixture-dump: no case %s\n", w.c_str());
      ++missing;
    }
  }
  return missing ? 1 : 0;
}
