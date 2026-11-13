#include "result.hpp"

#include <algorithm>
#include <set>

#include "json.hpp"

namespace verifier {

std::string_view status_name(Status s) {
  constexpr std::string_view names[] = {"MATCH", "DIFF", "MISSING", "AMBIGUOUS", "BADADDR", "LIBCODE"};
  return names[size_t(s)];
}

void Out::write(const std::string& s) { std::fwrite(s.data(), 1, s.size(), stdout); }
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
  static std::string memo_root;  // the root the memos are for (a run has one)
  static SvMap<std::string> memo;
  static std::unordered_map<std::string, std::optional<std::string>> dirs;  // nullopt: another drive than the root's
  if (root != memo_root) {
    memo.clear();
    dirs.clear();
    memo_root = root;
  }
  auto it = memo.find(path);
  if (it != memo.end()) return it->second;
  std::string key(path);
  std::string p(path), dir = dirname(p), base = basename(p), rel;
  bool by_dir = !base.empty() && base != "." && base != "..";
#ifdef _WIN32
  // the full path is the directory's and the name (no drive-relative directory like `C:`, no name the full path
  // changes: a stream, or trailing dots or spaces)
  by_dir = by_dir && (dir.empty() || (dir.size() >= 2 && dir.back() != ':')) && base.find(':') == std::string::npos &&
           base.back() != '.' && base.back() != ' ';
#endif
  if (by_dir) {
    auto d = dirs.find(dir);
    if (d == dirs.end()) d = dirs.emplace(dir, relpath_on_drive(dir.empty() ? "." : dir, root)).first;
    rel = !d->second ? p : *d->second == "." ? base : path_join(*d->second, base);  // another drive: as given
  } else {
    rel = relpath(p, root);
  }
  return memo.emplace(std::move(key), std::move(rel)).first->second;
}

void set_where(std::vector<Annotation>& anns, const std::string& root) {
  std::string_view path, where;  // the last file's (a file's annotations come together)
  for (auto& a : anns) {
    if (a.path.data() != path.data() || a.path.size() != path.size()) {
      path = a.path;
      where = keep_text(where_of(path, root));
    }
    a.where = where;
  }
}

namespace {

const std::function<Key(u64)>& by_va() {
  static const std::function<Key(u64)> f = [](u64 t) { return Key::of_va(t); };
  return f;
}

// an address field's target that resolves to nothing (an import is something; a compiler constant is by value)
void add_unresolved(const Field& f, const Image& img, const std::function<Key(u64)>& resolve,
                    std::set<std::string>& out) {
  if (img.imports.count(u64(f.value))) return;
  Key k = resolve(u64(f.value));
  if (k.kind == Key::UNRESOLVED) out.insert(std::string(k.name));
}

}  // namespace

std::optional<FnPair> compared_pair(const Annotation& ann, const Original& orig, const Rebuilt& reb,
                                    const Pairing& pairing) {
  u64 ova = ann.va;
  if (!orig.functions.contains(ova) || library_code(ann, orig)) return std::nullopt;
  const Pairing::Paired* pd = pairing.paired(ann);
  Lookup lk = pd ? pd->lookup : lookup_annotation(reb, ann, sig_flag(ann.flags), true);
  if (lk.vas.empty() || lk.nhits > 1) return std::nullopt;
  return FnPair{ova, orig.extent(ova), lk.vas[0], reb.extent(lk.vas[0])};
}

Result evaluate(const Annotation& ann, const Original& orig, const Rebuilt& reb, Pairing& pairing, Comparer& cmp,
                const std::string& root, bool show, Out& out, bool want_diff, DiffStore* diffs) {
  u64 ova = ann.va;
  Result rec;
  rec.va = ova;
  rec.orig = hex(ova);
  rec.name = ann.name;
  rec.kind = ann.kind;
  rec.src = ann.where.empty() ? where_of(ann.path, root) : std::string(ann.where);
  rec.src += ':';
  rec.src += std::to_string(ann.line);
  // pairing has looked the name up already (the same key: a compared annotation's name, its parameter list, code)
  Lookup own;
  const Lookup* lkp = &own;
  if (const Pairing::Paired* pd = pairing.paired(ann)) {
    lkp = &pd->lookup;
    rec.overloads = pd->overloads;
  } else {
    own = lookup_annotation(reb, ann, sig_flag(ann.flags), true);
    rec.overloads = overloads_of_annotation(reb, ann);
  }
  const Lookup& lk = *lkp;
  if (!orig.functions.contains(ova)) {
    rec.status = Status::BadAddr;
    return rec;
  }
  if (const Linked* l = library_code(ann, orig)) {
    rec.status = Status::LibCode;
    rec.linked = true;
    rec.lib = l->lib;
    if (l->has_symbol) rec.symbol = l->symbol;
    return rec;
  }
  if (lk.vas.empty() || lk.nhits > 1) {
    rec.status = lk.vas.empty() ? Status::Missing : Status::Ambiguous;
    return rec;
  }
  rec.name = lk.qname;
  u64 rva = lk.vas[0];
  u64 oend = orig.extent(ova), rend = reb.extent(rva);
  FnPair fns{ova, oend, rva, rend};
  Problems probs = cmp.judge_function(fns);
  auto ocp = cmp.orig_code(ova, oend);
  const Code& oc = *ocp;
  // a match whose code decodes as the original's needs no decode of its own (same_code_fields)
  std::optional<std::vector<Field>> fields;
  if (probs.empty() && !show) fields = same_code_fields(oc, reb.img, rva, rend);
  auto rcp = fields ? ocp : cmp.rebuilt_code(rva, rend);
  const Code& rc = *rcp;  // the original's when the fields are known
  std::function<Key(u64)> resolve = [&](u64 t) { return pairing.resolve(t); };
  // the rebuilt side's names that resolve to nothing: what its branches out of the function and RIP-relative operands
  // refer to
  std::set<std::string> unresolved;
  for (const Field& f : fields ? std::span<const Field>(*fields) : rc.field_list)
    if (f.kind == F_EXT || f.kind == F_RIP) add_unresolved(f, reb.img, resolve, unresolved);
  rec.compared = true;
  rec.osize = i64(oc.code.size());  // padding after the last ret is not code, whichever side's extent reaches over it
  rec.rsize = i64(rc.code.size());
  rec.status = probs.empty() ? Status::Match : Status::Diff;
  rec.unresolved.assign(unresolved.begin(), unresolved.end());
  for (size_t i = 0; i < probs.size() && i < 8; ++i) rec.problems.push_back(probs[i].text());
  Toks ot, rt;  // the instructions as tokens, for the listing
  if (show) {
    ot = symbolise(oc, by_va(), false);
    rt = symbolise(rc, resolve, true);
    for (size_t k = 0; k < std::min(ot.size(), rt.size()); ++k) const_by_value(ot[k], rt[k], orig.img);
  }
  if (!probs.empty() || show) {
    DiffContext cx{resolve, &cmp.m, cmp.names};
    // the category the instructions give and the diff: functions of the code and its targets, kept between runs
    auto make = [&] {
      DiffReport e;
      e.category = classify_mnemonics(oc, rc);
      if (!e.category) {  // the same mnemonics in order: the operands decide, as tokens
        Toks a = symbolise(oc, by_va(), false), b = symbolise(rc, resolve, true);
        for (size_t k = 0; k < std::min(a.size(), b.size()); ++k) const_by_value(a[k], b[k], orig.img);
        if (!(a == b)) e.category = classify(a, b);
      }
      e.diff = code_diff(oc, rc, cx, want_diff);
      if (e.diff.first) {
        e.first_orig = oc.insn(oc.insns[e.diff.first->first]).text();
        e.first_rebuilt = rc.insn(rc.insns[e.diff.first->second]).text();
      }
      return e;
    };
    DiffReport e = diffs && want_diff && !show ? diffs->get(oc, rc, cx, make) : make();
    if (!probs.empty()) rec.category = e.category ? *e.category : probs[0].category;
    if (e.diff.differs) {
      if (e.diff.first)
        rec.first_diff =
            Result::FirstDiff{i64(e.diff.first->first), std::move(e.first_orig), std::move(e.first_rebuilt)};
      rec.has_diff = true;
      rec.diff = std::move(e.diff.lines);
    }
  }
  if (show) {
    out.print("--- " + lk.qname + "  orig " + std::to_string(rec.osize) + "B | rebuilt " + std::to_string(rec.rsize) +
              "B  " + (probs.empty() ? "MATCH" : "DIFF"));
    for (auto& p : probs) out.print("  problem " + p.text());
    for (size_t k = 0; k < std::max(oc.insns.size(), rc.insns.size()); ++k) {
      std::string x = k < oc.insns.size() ? oc.insn(oc.insns[k]).text() : "";
      std::string y = k < rc.insns.size() ? rc.insn(rc.insns[k]).text() : "";
      bool eq = k < ot.size() && k < rt.size() && ot[k] == rt[k];
      out.print(std::string(eq ? " " : "*") + " " + pad_right(x, 48) + " | " + y);
    }
  }
  pairing.release_code(fns);  // compared: the code is not needed again
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
    str_or_null(r.category ? std::optional<std::string>(category_name(*r.category)) : std::nullopt);
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
                     pad_right(r.category ? std::string(category_name(*r.category)) : "", 12) + " " + r.name;
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
