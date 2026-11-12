#include "result.hpp"

#include <algorithm>
#include <set>

#include "json.hpp"

namespace verifier {



std::string_view status_name(Status s) {
  constexpr std::string_view names[] = {"MATCH", "DIFF", "MISSING", "AMBIGUOUS", "BADADDR", "LIBCODE"};
  return names[size_t(s)];
}

void Out::write(const std::string& s) {
  text_ += s;
  std::fwrite(s.data(), 1, s.size(), stdout);
}
void Out::print(const std::string& line) { write(line + "\n"); }

namespace {

std::string pad_left(const std::string& s, size_t w) { return s.size() >= w ? s : std::string(w - s.size(), ' ') + s; }
std::string pad_right(const std::string& s, size_t w) { return s.size() >= w ? s : s + std::string(w - s.size(), ' '); }

// the first n characters (UTF-8 code points)
std::string head_chars(const std::string& s, size_t n) {
  size_t i = 0, chars = 0;
  while (i < s.size() && chars < n) {
    unsigned char c = static_cast<unsigned char>(s[i]);
    i += c < 0x80 ? 1 : c < 0xe0 ? 2 : c < 0xf0 ? 3 : 4;
    ++chars;
  }
  return s.substr(0, std::min(i, s.size()));
}

}  // namespace

// a source path as the report gives it (relative to the root); many annotations share a file, and many files a
// directory (relpath's work is the directory's)
const std::string& where_of(std::string_view path, const std::string& root) {
  static std::unordered_map<std::string, std::string> memo, dirs;
  std::string key = root + '\0' + std::string(path);
  auto it = memo.find(key);
  if (it != memo.end()) return it->second;
  std::string p(path), dir = dirname(p), base = basename(p), rel;
#ifdef _WIN32
  bool by_dir = false;  // another drive than the root's: relpath gives the path as it is
#else
  bool by_dir = !base.empty() && base != "." && base != "..";
#endif
  if (by_dir) {
    std::string dkey = root + '\0' + dir;
    auto d = dirs.find(dkey);
    if (d == dirs.end()) d = dirs.emplace(std::move(dkey), relpath(dir.empty() ? "." : dir, root)).first;
    rel = d->second == "." ? base : path_join(d->second, base);
  } else {
    rel = relpath(p, root);
  }
  return memo.emplace(std::move(key), std::move(rel)).first->second;
}

namespace {

const std::function<Key(u64)>& by_va() {
  static const std::function<Key(u64)> f = [](u64 t) { return Key::of_va(t); };
  return f;
}

// the original's RIP-relative operand stands for its bytes where the rebuilt one is a compiler constant (by value)
void const_by_value(Tok& o, const Tok& r, const Image& O) {
  if (r.ops.size() != o.ops.size()) return;
  for (size_t z = 0; z < r.ops.size(); ++z) {
    if (r.ops[z].k == Op::CONST && o.ops[z].k == Op::MSYM) {
      Op c{};
      c.k = Op::CONST;
      c.key.name = O.bytes(o.ops[z].key.va, i64(r.ops[z].bytes().size()));
      o.ops[z] = c;
    }
  }
}

void add_unresolved(const Tok& t, std::set<std::string>& out) {
  for (auto& op : t.ops)
    if ((op.k == Op::SYM || op.k == Op::MSYM) && op.key.kind == Key::UNRESOLVED) out.insert(std::string(op.key.name));
}

// Whether the two functions' tokens are equal, decided from their kept form: instructions with the same size,
// field layout and bytes outside the fields have the same operands except where the address matters
// (Lean::addressed), and only those are decoded again and compared as tokens. false when not known to be equal
// (the full comparison decides); when true, `unresolved` has the rebuilt tokens' unresolved names.
bool same_tokens(const Code& oc, const Code& rc, u64 ova, u64 oend, u64 rva, u64 rend, const Image& O, const Image& R,
                 const std::function<Key(u64)>& resolve, std::set<std::string>& unresolved) {
  if (oc.insns.size() != rc.insns.size()) return false;
  for (size_t k = 0; k < oc.insns.size(); ++k) {
    const Lean &a = oc.insns[k], &b = rc.insns[k];
    auto fa = oc.fields(a), fb = rc.fields(b);
    if (a.mnem != b.mnem || !same_layout(a, fa, b, fb) || !same_outside_fields(oc.bytes(a), rc.bytes(b), fa))
      return false;
    if (!a.addressed && !b.addressed) continue;
    Tok to = symbolise_one(oc.insn(a), ova, oend, by_va(), O, false);
    Tok tr = symbolise_one(rc.insn(b), rva, rend, resolve, R, true);
    const_by_value(to, tr, O);
    if (!(to == tr)) return false;
    add_unresolved(tr, unresolved);
  }
  return true;
}

}  // namespace

Result evaluate(const Annotation& ann, const Original& orig, const Rebuilt& reb, Pairing& pairing, Comparer& cmp,
                const std::string& root, bool show, Out& out, bool want_diff, DiffStore* diffs) {
  u64 ova = ann.va;
  Result rec;
  rec.va = ova;
  rec.orig = hex(ova);
  rec.name = ann.name;
  rec.kind = ann.kind;
  rec.src = where_of(ann.path, root) + ":" + std::to_string(ann.line);
  // pairing has looked the name up already (the same key: a compared annotation's name, its parameter list, code)
  Lookup lk;
  if (const Pairing::Paired* pd = pairing.paired(ann)) {
    lk = pd->lookup;
    rec.overloads = pd->overloads;
  } else {
    lk = reb.lookup(ann.name, sig_flag(ann.flags), true);
    rec.overloads = reb.overloads_of(ann.name);
  }
  if (!orig.functions.contains(ova)) {
    rec.status = Status::BadAddr;
    return rec;
  }
  if (is_counted(ann.kind) && orig.linked.count(ova)) {
    rec.status = Status::LibCode;
    auto& l = orig.linked.at(ova);
    rec.linked = true;
    rec.lib = l.lib;
    if (l.has_symbol) rec.symbol = l.symbol;
    return rec;
  }
  if (lk.vas.empty() || lk.nhits > 1) {
    rec.status = lk.vas.empty() ? Status::Missing : Status::Ambiguous;
    return rec;
  }
  rec.name = lk.qname;
  u64 rva = lk.vas[0];
  u64 oend = orig.extent(ova), rend = reb.extent(rva);
  Problems probs = cmp.function(ova, oend, rva, rend);
  auto ocp = cmp.orig_code(ova, oend), rcp = cmp.rebuilt_code(rva, rend);  // decoded by the comparison
  const Code &oc = *ocp, &rc = *rcp;
  std::function<Key(u64)> resolve = [&](u64 t) { return pairing.resolve(t); };
  std::set<std::string> unresolved;
  bool same;
  if (probs.empty() && !show) {
    // a match: the comparison accepted every address field, so no diff is shown; only the rebuilt side's names that
    // resolve to nothing are reported (unaddressed instructions have none)
    for (auto& b : rc.insns)
      if (b.addressed) add_unresolved(symbolise_one(rc.insn(b), rva, rend, resolve, reb.img, true), unresolved);
    same = true;
  } else {
    same = same_tokens(oc, rc, ova, oend, rva, rend, orig.img, reb.img, resolve, unresolved);
  }
  Toks ot, rt;  // only when the report shows instructions
  if (!same || show) {
    ot = symbolise(oc, by_va(), false);
    rt = symbolise(rc, resolve, true);
    for (size_t k = 0; k < std::min(ot.size(), rt.size()); ++k) const_by_value(ot[k], rt[k], orig.img);
    unresolved.clear();
    for (auto& t : rt) add_unresolved(t, unresolved);
    same = ot == rt;
  }
  rec.compared = true;
  auto offsets = [](const Code& c) {
    std::vector<u32> v;
    for (auto& l : c.insns) v.push_back(l.off);
    return v;
  };
  // a DIFF's category and diff, kept between runs (a function of the tokens): read from the store when it has them
  std::optional<DiffStore::Entry> kept;
  if (diffs && !same && !probs.empty() && want_diff) kept = diffs->get(offsets(oc), offsets(rc), ot, rt, cmp.names);
  if (!probs.empty()) rec.category = same ? probs[0].category : kept ? kept->category : classify(ot, rt);
  rec.osize = i64(oc.code.size());  // padding after the last ret is not code, whichever side's extent reaches over it
  rec.rsize = i64(rc.code.size());
  rec.status = probs.empty() ? Status::Match : Status::Diff;
  rec.unresolved.assign(unresolved.begin(), unresolved.end());
  for (size_t i = 0; i < probs.size() && i < 8; ++i) rec.problems.push_back(probs[i].category + ": " + probs[i].detail);
  if (!same) {
    for (size_t k = 0; k < std::min(ot.size(), rt.size()); ++k) {
      if (ot[k] == rt[k]) continue;
      rec.first_diff = Result::FirstDiff{i64(k), oc.insn(oc.insns[k]).text(), rc.insn(rc.insns[k]).text()};
      break;
    }
    rec.has_diff = true;
    if (want_diff) rec.diff = kept ? std::move(kept->diff) : insn_diff(offsets(oc), offsets(rc), ot, rt, cmp.names);
  }
  if (show) {
    out.print("--- " + lk.qname + "  orig " + std::to_string(rec.osize) + "B | rebuilt " + std::to_string(rec.rsize) +
              "B  " + (probs.empty() ? "MATCH" : "DIFF"));
    for (auto& [c, d] : probs) out.print("  problem " + c + ": " + d);
    for (size_t k = 0; k < std::max(oc.insns.size(), rc.insns.size()); ++k) {
      std::string x = k < oc.insns.size() ? oc.insn(oc.insns[k]).text() : "";
      std::string y = k < rc.insns.size() ? rc.insn(rc.insns[k]).text() : "";
      bool eq = k < ot.size() && k < rt.size() && ot[k] == rt[k];
      out.print(std::string(eq ? " " : "*") + " " + pad_right(x, 48) + " | " + y);
    }
  }
  pairing.release_code(ova, oend, rva, rend);  // compared: the code is not needed again
  return rec;
}

void write_result(std::string& out, const Result& r, int level) {
  json::ObjectWriter o(out, level);
  int in = o.value_level();
  auto str = [&](const char* k, const std::string& v) {
    o.key(k);
    json::put_quoted(out, v);
  };
  auto strs = [&](const char* k, const std::vector<std::string>& v) {
    o.key(k);
    json::put_strings(out, v, in);
  };
  auto str_or_null = [&](const std::optional<std::string>& v) {
    if (v)
      json::put_quoted(out, *v);
    else
      out += "null";
  };
  str("orig", r.orig);
  str("name", r.name);
  str("kind", std::string(kind_name(r.kind)));
  str("src", r.src);
  if (r.overloads.size() > 1) strs("overloads", r.overloads);
  if (r.compared) {
    o.key("osize");
    out += std::to_string(r.osize);
    o.key("rsize");
    out += std::to_string(r.rsize);
  }
  str("status", std::string(status_name(r.status)));
  if (r.linked) {
    o.key("library");
    out += '[';
    auto indent = [&](int level) {
      out += '\n';
      out.append(2 * size_t(level), ' ');
    };
    indent(in + 1);
    json::put_quoted(out, r.lib);
    out += ',';
    indent(in + 1);
    str_or_null(r.symbol);
    indent(in);
    out += ']';
  }
  if (r.compared) {
    o.key("category");
    str_or_null(r.category);
    strs("unresolved", r.unresolved);
    strs("problems", r.problems);
    if (r.first_diff) {
      o.key("first_diff");
      json::ObjectWriter f(out, in);
      f.key("index");
      out += std::to_string(r.first_diff->index);
      f.key("orig");
      json::put_quoted(out, r.first_diff->orig);
      f.key("rebuilt");
      json::put_quoted(out, r.first_diff->rebuilt);
      f.end();
    }
    if (r.has_diff) strs("diff", r.diff);
  }
  o.end();
}

std::string result_line(const Result& r, const std::string& module) {
  std::string line = pad_right(std::string(status_name(r.status)), 9) + " " + r.orig + " " +
                     pad_left(r.compared ? std::to_string(r.osize) : "-", 5) + "/" +
                     pad_right(r.compared ? std::to_string(r.rsize) : "-", 5) + " " +
                     pad_right(r.category.value_or(""), 12) + " " + r.name;
  if (r.first_diff) {
    line += "\n            @" + std::to_string(r.first_diff->index) + ": orig `" + r.first_diff->orig +
            "` | rebuilt `" + r.first_diff->rebuilt + "`";
  } else if (!r.problems.empty()) {
    line += "\n            " + head_chars(r.problems[0], 160);
  }
  if (!r.unresolved.empty()) {
    std::vector<std::string> xs;
    for (auto& x : r.unresolved) xs.push_back(head_chars(x, 90));
    line += "\n            unresolved: " + join(xs, ", ");
  }
  if (r.overloads.size() > 1 && r.status != Status::Match)
    line += "\n            overloads: " + head_chars(join(r.overloads, " "), 200) +
            " (pick one: `// FUNCTION: " + module + " 0x... (<params>)`)";
  return line;
}

}  // namespace verifier
