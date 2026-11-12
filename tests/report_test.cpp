// What a DIFF reports: the category, the instruction diff and its alignment, the JSON writer.
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
  rs[0].kind = Kind::Function;
  rs[0].src = "a.cpp:1";
  rs[0].status = Status::BadAddr;
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
  rs[1].status = Status::LibCode;
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
  rs[2].status = Status::Match;
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
  rs[3].status = Status::Diff;
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

Problems json_escaping() {
  // put_quoted against the plain definition: each character as it is but control characters, '"' and '\\'
  auto plain = [](std::string_view s) {
    std::string o = "\"";
    for (unsigned char c : s) {
      if (c == '"')
        o += "\\\"";
      else if (c == '\\')
        o += "\\\\";
      else if (c == '\n')
        o += "\\n";
      else if (c == '\r')
        o += "\\r";
      else if (c == '\t')
        o += "\\t";
      else if (c < 0x20) {
        char b[8];
        std::snprintf(b, sizeof b, "\\u%04x", c);
        o += b;
      } else
        o += char(c);
    }
    return o + "\"";
  };
  std::mt19937_64 g(5);
  const char pool[] = {'a',    'Z',    ' ',    '~',    '"',    '\\',   '\n',   '\r',   '\t',
                       '\x01', '\x1f', '\x20', '\x7f', '\x80', '\xc3', '\xa9', '\xff', '\0'};
  for (int n = 0; n < 20000; ++n) {
    std::string s(size_t(g() % 41), 'x');
    for (auto& c : s) c = g() % 3 ? 'a' + char(g() % 26) : pool[g() % sizeof pool];
    std::string got;
    json::put_quoted(got, s);
    if (got != plain(s)) return {{"json", "escaping " + hex_bytes(s)}};
  }
  return {};
}

}  // namespace

void add_report_cases(Cases& cases) {
  cases.insert(cases.end(), {
      {"category: other branch target", "reference", [] { return category(0, 0x180001b00, true); }},
      {"category: other immediate", "immediate", [] { return category(1, 0, false); }},
      {"instruction diff", nullptr, instruction_diff},
      {"linear matcher", nullptr, [] { return linear_matcher(fixtures()); }},
      {"report writer", nullptr, report_writer},
      {"unit: JSON string escaping", nullptr, json_escaping},
  });
}

}  // namespace verifier::test
