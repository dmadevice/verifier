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

#include "align.hpp"
#include "support.hpp"

namespace verifier::test {

namespace {

Findings category(i64 rimm, u64 rtarget, bool branch) {
  Toks a, b;
  if (branch) {
    a = {{"cmp", {opm("rcx", 0x48, 1), opi(0)}}, {"jne", {opsym(Key::of_va(0x180001a00))}}};
    b = {{"cmp", {opm("rcx", 0x48, 1), opi(0)}}, {"jne", {opsym(Key::of_va(rtarget))}}};
  } else {
    a = {{"cmp", {opm("rcx", 0x48, 1), opi(0)}}};
    b = {{"cmp", {opm("rcx", 0x48, 1), opi(rimm)}}};
  }
  return {{std::string(category_name(classify(a, b))), ""}};
}

// what is wrong with an alignment of a and b: the opcodes must cover both in order, an equal run must be equal,
// adjacent opcodes must not share a tag ("" when nothing is wrong)
std::string alignment_fault(const std::vector<u32>& a, const std::vector<u32>& b, const std::vector<Opcode>& ops) {
  size_t i = 0, j = 0;
  char last = 0;
  for (auto& o : ops) {
    if (o.i1 != i || o.j1 != j || o.i2 < o.i1 || o.j2 < o.j1) return "not contiguous";
    if (o.tag == last || (o.tag != 'e' && last && last != 'e')) return "adjacent opcodes share a tag";
    bool da = o.i2 > o.i1, db = o.j2 > o.j1;
    if ((o.tag == 'e' && (o.i2 - o.i1 != o.j2 - o.j1 || !da)) || (o.tag == 'r' && !(da && db)) ||
        (o.tag == 'd' && (!da || db)) || (o.tag == 'i' && (da || !db)))
      return std::string("bad ") + o.tag;
    if (o.tag == 'e' && !std::equal(a.begin() + long(o.i1), a.begin() + long(o.i2), b.begin() + long(o.j1)))
      return "equal run differs";
    i = o.i2;
    j = o.j2;
    last = o.tag;
  }
  if (i != a.size() || j != b.size()) return "does not cover both";
  return "";
}

// The alignment against what any shortest-edit-script aligner must do: each diff gives back both sequences, equal
// inputs give one equal run (nothing for empty ones), and the same inputs the same diff. Random sequences over small
// alphabets (many repeats: the Myers part), larger ones (the patience part), and a tiny cost limit (the split taken
// where the search got furthest).
Findings alignment_properties() {
  std::mt19937_64 g(11);
  for (int n = 0; n < 4000; ++n) {
    size_t alphabet = 1 + g() % (n % 4 == 0 ? 200 : 6), la = g() % (n % 50 == 0 ? 600 : 40), lb = g() % 40;
    if (n % 3 == 0) lb = la;
    std::vector<u32> a(la), b(lb);
    for (auto& x : a) x = u32(g() % alphabet);
    if (n % 3 == 0) {
      b = a;  // b: a edited in a few places
      for (int e = int(g() % 5); e > 0 && !b.empty(); --e) {
        size_t at = g() % b.size();
        switch (g() % 3) {
          case 0:
            b.erase(b.begin() + long(at));
            break;
          case 1:
            b.insert(b.begin() + long(at), u32(g() % alphabet));
            break;
          default:
            b[at] = u32(g() % alphabet);
        }
      }
    } else {
      for (auto& x : b) x = u32(g() % alphabet);
    }
    size_t cost = n % 7 == 0 ? 2 : 1024;
    auto ops = align(a, b, cost);
    if (auto why = alignment_fault(a, b, ops); !why.empty())
      return {{"alignment", why + " (case " + std::to_string(n) + ")"}};
    auto again = align(a, b, cost);
    bool same = again.size() == ops.size();
    for (size_t k = 0; same && k < ops.size(); ++k)
      same = again[k].tag == ops[k].tag && again[k].i1 == ops[k].i1 && again[k].i2 == ops[k].i2 &&
             again[k].j1 == ops[k].j1 && again[k].j2 == ops[k].j2;
    if (!same) return {{"alignment", "not deterministic (case " + std::to_string(n) + ")"}};
    if (cost > a.size() + b.size()) {  // under the cost limit: a shortest script
      size_t len = 0;
      for (auto& o : ops)
        if (o.tag != 'e') len += (o.i2 - o.i1) + (o.j2 - o.j1);
      if (len != edit_distance(a, b)) return {{"alignment", "not a shortest script (case " + std::to_string(n) + ")"}};
    }
    auto self = align(a, a, cost);
    if (!(a.empty() ? self.empty() : self.size() == 1 && self[0].tag == 'e'))
      return {{"alignment", "equal inputs differ (case " + std::to_string(n) + ")"}};
  }
  return {};
}

// the opcodes as text: "e0-2/0-2 i2-2/2-3"
std::string opcodes_text(const std::vector<Opcode>& ops) {
  std::string out;
  for (auto& o : ops)
    out += (out.empty() ? "" : " ") + std::string(1, o.tag) + std::to_string(o.i1) + "-" + std::to_string(o.i2) + "/" +
           std::to_string(o.j1) + "-" + std::to_string(o.j2);
  return out;
}

Findings alignment_cases() {
  struct C {
    const char* name;
    std::vector<u32> a, b;
    const char* want;
  };
  std::vector<C> cases = {
      {"insertion", {1, 2, 3, 4}, {1, 2, 9, 3, 4}, "e0-2/0-2 i2-2/2-3 e2-4/3-5"},
      {"deletion", {1, 2, 9, 3, 4}, {1, 2, 3, 4}, "e0-2/0-2 d2-3/2-2 e3-5/2-4"},
      {"replaced block", {1, 2, 3, 4, 5}, {1, 7, 8, 9, 5}, "e0-1/0-1 r1-4/1-4 e4-5/4-5"},
      // two blocks swapped: one stays aligned, the other is deleted where it was and inserted where it went
      {"reordered blocks", {1, 2, 3, 4, 5, 6}, {4, 5, 6, 1, 2, 3}, "d0-3/0-0 e3-6/0-3 i6-6/3-6"},
      // repeats only, no common prefix or suffix: Myers, a shortest script
      {"no unique element", {1, 2, 1, 2, 1}, {2, 1, 2, 1, 2}, "d0-1/0-0 e1-5/0-4 i5-5/4-5"},
      {"empty", {}, {1}, "i0-0/0-1"},
      // a branch (9) twice on one side and once on the other, the code between the same: three instructions replaced
      // by one (`setg; test; jz` by `jle`), the rest aligned, the single branch with the second
      {"duplicate branch", {7, 8, 9, 3, 4, 5, 9, 6}, {10, 3, 4, 5, 9, 6}, "r0-3/0-1 e3-8/1-6"},
  };
  Findings bad;
  for (auto& c : cases) {
    std::string got = opcodes_text(align(c.a, c.b));
    if (got != c.want) bad.push_back({"alignment", std::string(c.name) + ": " + got});
  }
  return bad;
}

// The instruction diff of two small functions in synthetic images: a REX prefix that changes nothing (an encoding
// difference, shown as one), an inserted instruction, a call to the function the rebuilt one's name stands for, and
// a branch inside the function whose target moves with the code (the same) or to another instruction (not).
Findings instruction_diff() {
  Side os(0), rs(0x200);
  u64 of = os.put(TEXT, Bytes("\xc3", 1)), rf = rs.put(TEXT, Bytes("\xc3", 1));  // the callee
  u64 o = os.reserve(TEXT, 0x20), r = rs.reserve(TEXT, 0x20);
  // push rbx; je pop; call f; pop rbx; ret
  Bytes ob = Bytes("\x53\x74\x05", 3) + call(o + 3, of) + Bytes("\x5b\xc3", 2);
  // push rbx (40 53); je pop; nop; call f; pop rbx; ret
  auto rebuilt = [&](u8 je) {
    return Bytes("\x40\x53\x74", 3) + char(je) + Bytes("\x90", 1) + call(r + 5, rf) + Bytes("\x5b\xc3", 2);
  };
  os.write(o, ob);
  Image O = os.image();
  NameMap names{{of, "Callee"}};
  auto resolve = [&](u64 t) { return t == rf ? Key::of_va(of) : Key::named(Key::UNRESOLVED, "x"); };
  Findings bad;
  for (u8 je : {u8(6), u8(7)}) {
    rs.write(r, rebuilt(je));
    Image R = rs.image();
    Code oc(O, o, o + ob.size()), rc(R, r, r + rebuilt(je).size());
    CodeDiff d = code_diff(oc, rc, {resolve, nullptr, name_of(names)}, true, 1);
    std::vector<std::string> want = je == 6 ? std::vector<std::string>{"@0",
                                                                       "- push rbx  ; encoding 53",
                                                                       "+ push rbx  ; encoding 4053",
                                                                       "  jz <+0x8>",
                                                                       "+ nop",
                                                                       "  call Callee"}
                                            : std::vector<std::string>{"@0",
                                                                       "- push rbx  ; encoding 53",
                                                                       "+ push rbx  ; encoding 4053",
                                                                       "- jz <+0x8>",
                                                                       "+ jz <+0xb>",
                                                                       "+ nop",
                                                                       "  call Callee"};
    if (d.lines != want) bad.push_back({"diff", join(d.lines, " | ")});
    if (!d.differs || !d.first || d.first->first != 0 || d.first->second != 0)
      bad.push_back({"diff", "first difference not at the push"});
  }
  // the same code: no difference
  Code a(O, o, o + ob.size()), b(O, o, o + ob.size());
  CodeDiff d = code_diff(a, b, {[](u64 t) { return Key::of_va(t); }, nullptr, name_of(names)}, true);
  if (d.differs || !d.lines.empty() || d.first) bad.push_back({"diff", "the same code differs"});
  return bad;
}

// A condition computed into a register and tested (`setg; test; jz`) where the rebuilt function branches on it
// (`jle`): those three replaced by the one, and the earlier branch to the same place the same although the original's
// is a near branch (the code between is longer) and the rebuilt one's a short one.
Findings branch_forms() {
  Side os(0), rs(0x200);
  // test ecx, ecx; jz near ret; cmp edx, 0; setg al; test al, al; jz ret; mov eax, 1; ret
  Bytes ob("\x85\xc9\x0f\x84\x0f\x00\x00\x00\x83\xfa\x00\x0f\x9f\xc0\x84\xc0\x74\x05\xb8\x01\x00\x00\x00\xc3", 24);
  // test ecx, ecx; jz ret; cmp edx, 0; jle ret; mov eax, 1; ret
  Bytes rb("\x85\xc9\x74\x0a\x83\xfa\x00\x7e\x05\xb8\x01\x00\x00\x00\xc3", 15);
  u64 o = os.reserve(TEXT, 0x20), r = rs.reserve(TEXT, 0x20);
  os.write(o, ob);
  rs.write(r, rb);
  Image O = os.image(), R = rs.image();
  Code oc(O, o, o + ob.size()), rc(R, r, r + rb.size());
  NameMap names;
  CodeDiff d = code_diff(oc, rc, {[](u64 t) { return Key::of_va(t); }, nullptr, name_of(names)}, true, 1);
  std::vector<std::string> want = {"@2",           "  cmp edx, 0x0", "- setg al",     "- test al, al",
                                   "- jz <+0x17>", "+ jle <+0xe>",   "  mov eax, 0x1"};
  Findings bad;
  if (d.lines != want) bad.push_back({"diff", join(d.lines, " | ")});
  if (!d.first || d.first->first != 3 || d.first->second != 3) bad.push_back({"diff", "first difference not at setg"});
  // Two flags tested, the two returns in the other order. A shortest script aligns either return with its own; the
  // one aligning the return the first branch goes to keeps that branch the same: 6 lines changed, not 8.
  // movzx eax, [rcx+0x62]; test al, al; jnz A; movzx eax, [rcx+0x63]; test al, al; jz B; A: movzx eax, al; ret;
  // B: xor eax, eax; ret
  Bytes ob2("\x0f\xb6\x41\x62\x84\xc0\x75\x08\x0f\xb6\x41\x63\x84\xc0\x74\x04\x0f\xb6\xc0\xc3\x33\xc0\xc3", 23);
  // the same to the second jnz A; then xor eax, eax; ret; A: movzx eax, al; ret
  Bytes rb2("\x0f\xb6\x41\x62\x84\xc0\x75\x0b\x0f\xb6\x41\x63\x84\xc0\x75\x03\x33\xc0\xc3\x0f\xb6\xc0\xc3", 23);
  os.write(o, ob2);
  rs.write(r, rb2);
  Image O2 = os.image(), R2 = rs.image();
  Code oc2(O2, o, o + ob2.size()), rc2(R2, r, r + rb2.size());
  d = code_diff(oc2, rc2, {[](u64 t) { return Key::of_va(t); }, nullptr, name_of(names)}, true, 1);
  size_t changed = std::count_if(d.lines.begin(), d.lines.end(), [](auto& l) { return l[0] == '-' || l[0] == '+'; });
  if (changed != 6 || !d.first || d.first->first != 5) bad.push_back({"diff", join(d.lines, " | ")});
  return bad;
}

// the report's records, written as they are made, are the text json::dump gives for the same document
Findings report_writer() {
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
  rs[3].category = Category::Regalloc;
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
  Findings bad;
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

Findings json_escaping() {
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
  cases.insert(cases.end(),
               {
                   {"category: other branch target", "reference", [] { return category(0, 0x180001b00, true); }},
                   {"category: other immediate", "immediate", [] { return category(1, 0, false); }},
                   {"alignment: properties", nullptr, alignment_properties},
                   {"alignment: hand cases", nullptr, alignment_cases},
                   {"instruction diff", nullptr, instruction_diff},
                   {"branch forms", nullptr, branch_forms},
                   {"report writer", nullptr, report_writer},
                   {"unit: JSON string escaping", nullptr, json_escaping},
               });
}

}  // namespace verifier::test
