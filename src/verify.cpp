#include "verify.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>

#include "content_hash.hpp"
#include "replay.hpp"
#include "sha256.hpp"
#include "source_cache.hpp"
#include "timing.hpp"

namespace verifier {

using json::Value;

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

// a source path as the report gives it (relative to the root); many annotations share a file
const std::string& where_of(std::string_view path, const std::string& root) {
  static std::unordered_map<std::string, std::string> memo;
  std::string key = root + '\0' + std::string(path);
  auto it = memo.find(key);
  if (it == memo.end()) it = memo.emplace(std::move(key), relpath(std::string(path), root)).first;
  return it->second;
}

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
    if (a.mnem != b.mnem || !same_layout(a, fa, b, fb) || !same_outside_fields(oc.bytes(a), rc.bytes(b), fa)) return false;
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
  if (!orig.functions.contains(ova)) { rec.status = "BADADDR"; return rec; }
  if (is_counted(ann.kind) && orig.linked.count(ova)) {
    rec.status = "LIBCODE";
    auto& l = orig.linked.at(ova);
    rec.linked = true;
    rec.lib = l.lib;
    if (l.has_symbol) rec.symbol = l.symbol;
    return rec;
  }
  if (lk.vas.empty() || lk.nhits > 1) { rec.status = lk.vas.empty() ? "MISSING" : "AMBIGUOUS"; return rec; }
  rec.name = lk.qname;
  u64 rva = lk.vas[0];
  u64 oend = orig.extent(ova), rend = reb.extent(rva);
  Problems probs = cmp.function(ova, oend, rva, rend);
  auto ocp = cmp.orig_code(ova, oend), rcp = cmp.rebuilt_code(rva, rend);   // decoded by the comparison
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
  Toks ot, rt;   // only when the report shows instructions
  if (!same || show) {
    ot = symbolise(oc, by_va(), false);
    rt = symbolise(rc, resolve, true);
    for (size_t k = 0; k < std::min(ot.size(), rt.size()); ++k) const_by_value(ot[k], rt[k], orig.img);
    unresolved.clear();
    for (auto& t : rt) add_unresolved(t, unresolved);
    same = ot == rt;
  }
  rec.compared = true;
  auto offsets = [](const Code& c) { std::vector<u32> v; for (auto& l : c.insns) v.push_back(l.off); return v; };
  // a DIFF's category and diff, kept between runs (a function of the tokens): read from the store when it has them
  std::optional<DiffStore::Entry> kept;
  if (diffs && !same && !probs.empty() && want_diff) kept = diffs->get(offsets(oc), offsets(rc), ot, rt, cmp.names);
  if (!probs.empty()) rec.category = same ? probs[0].first : kept ? kept->category : classify(ot, rt);
  rec.osize = i64(oend - ova);
  rec.rsize = i64(rend - rva);
  rec.status = probs.empty() ? "MATCH" : "DIFF";
  rec.unresolved.assign(unresolved.begin(), unresolved.end());
  for (size_t i = 0; i < probs.size() && i < 8; ++i) rec.problems.push_back(probs[i].first + ": " + probs[i].second);
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
    out.print("--- " + lk.qname + "  orig " + std::to_string(oend - ova) + "B | rebuilt " + std::to_string(rend - rva) + "B  " +
              (probs.empty() ? "MATCH" : "DIFF"));
    for (auto& [c, d] : probs) out.print("  problem " + c + ": " + d);
    for (size_t k = 0; k < std::max(oc.insns.size(), rc.insns.size()); ++k) {
      std::string x = k < oc.insns.size() ? oc.insn(oc.insns[k]).text() : "";
      std::string y = k < rc.insns.size() ? rc.insn(rc.insns[k]).text() : "";
      bool eq = k < ot.size() && k < rt.size() && ot[k] == rt[k];
      out.print(std::string(eq ? " " : "*") + " " + pad_right(x, 48) + " | " + y);
    }
  }
  pairing.release_code(ova, oend, rva, rend);   // compared: the code is not needed again
  return rec;
}

void write_result(std::string& out, const Result& r, int level) {
  json::ObjectWriter o(out, level);
  int in = o.value_level();
  auto str = [&](const char* k, const std::string& v) { o.key(k); json::put_quoted(out, v); };
  auto strs = [&](const char* k, const std::vector<std::string>& v) { o.key(k); json::put_strings(out, v, in); };
  auto str_or_null = [&](const std::optional<std::string>& v) {
    if (v) json::put_quoted(out, *v);
    else out += "null";
  };
  str("orig", r.orig);
  str("name", r.name);
  str("kind", r.kind);
  str("src", r.src);
  if (r.overloads.size() > 1) strs("overloads", r.overloads);
  if (r.compared) {
    o.key("osize");
    out += std::to_string(r.osize);
    o.key("rsize");
    out += std::to_string(r.rsize);
  }
  str("status", r.status);
  if (r.linked) {
    o.key("library");
    out += '[';
    auto indent = [&](int level) { out += '\n'; out.append(2 * size_t(level), ' '); };
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
  std::string line = pad_right(r.status, 9) + " " + r.orig + " " + pad_left(r.compared ? std::to_string(r.osize) : "-", 5) + "/" +
                     pad_right(r.compared ? std::to_string(r.rsize) : "-", 5) + " " + pad_right(r.category.value_or(""), 12) + " " +
                     r.name;
  if (r.first_diff) {
    line += "\n            @" + std::to_string(r.first_diff->index) + ": orig `" + r.first_diff->orig + "` | rebuilt `" + r.first_diff->rebuilt + "`";
  } else if (!r.problems.empty()) {
    line += "\n            " + head_chars(r.problems[0], 160);
  }
  if (!r.unresolved.empty()) {
    std::vector<std::string> xs;
    for (auto& x : r.unresolved) xs.push_back(head_chars(x, 90));
    line += "\n            unresolved: " + join(xs, ", ");
  }
  if (r.overloads.size() > 1 && r.status != "MATCH")
    line += "\n            overloads: " + head_chars(join(r.overloads, " "), 200) + " (pick one: `// FUNCTION: " + module + " 0x... (<params>)`)";
  return line;
}

std::vector<GlobalDiff> check_globals(const std::vector<Annotation>& anns, const std::function<std::vector<u64>(const std::string&)>& lookup,
                                      const std::unordered_map<u64, u64>& reb_to_orig, Comparer& cmp) {
  const Image &O = *cmp.O, &R = *cmp.R;
  std::vector<const Annotation*> sorted;
  for (auto& a : anns) sorted.push_back(&a);
  std::stable_sort(sorted.begin(), sorted.end(), [](auto* x, auto* y) { return x->va < y->va; });
  std::vector<GlobalDiff> out;
  for (auto* a : sorted) {
    u64 va = a->va;
    if (a->kind != "GLOBAL" || !O.flags(va) || O.writable(va) || O.executable(va)) continue;
    for (u64 rva : lookup(a->name)) {
      auto it = reb_to_orig.find(rva);
      if (it == reb_to_orig.end() || it->second != va || R.writable(rva) || R.executable(rva)) continue;
      auto p = cmp.rodata(va, rva);
      if (p) out.push_back({a, p->second});
    }
  }
  return out;
}

namespace {

struct Totals {
  std::set<u64> matched;
  Value fields = Value::object();
  std::vector<const Result*> libcode;
};

// counts, most first (ties by name)
std::vector<std::pair<std::string, i64>> by_count(const std::map<std::string, i64>& counts) {
  std::vector<std::pair<std::string, i64>> v(counts.begin(), counts.end());
  std::stable_sort(v.begin(), v.end(), [](auto& a, auto& b) { return a.second > b.second; });
  return v;
}

std::string count_list(const std::vector<std::pair<std::string, i64>>& v) {   // "a 3, b 1"
  std::vector<std::string> parts;
  for (auto& [k, n] : v) parts.push_back(k + " " + std::to_string(n));
  return join(parts, ", ");
}

Totals summarize(const std::vector<Result>& results, const Original& orig, Out& out, const std::string& module) {
  Totals t;
  for (auto& r : results)
    if (r.status == "MATCH" && is_counted(r.kind)) t.matched.insert(r.va);
  std::pair<u64, u64> funclets{0, 0};
  if (auto it = orig.img.pogo.find(".text$x"); it != orig.img.pogo.end()) funclets = it->second;
  size_t universe = 0;
  u64 ubytes = 0, mbytes = 0, lib_bytes = 0;
  for (const IdaFunction& f : orig.functions) {
    u64 ea = f.ea;
    if (f.lib || f.thunk || orig.linked.count(ea) || (funclets.first <= ea && ea < funclets.second)) continue;
    ++universe;
    ubytes += f.size;
  }
  for (u64 v : t.matched) mbytes += orig.functions.at(v).size;
  std::map<std::string, i64> cat_counts, lib_counts;
  size_t differ = 0;
  for (auto& r : results) {
    if (r.status == "MATCH") continue;
    ++differ;
    ++cat_counts[r.category ? *r.category : r.status];
  }
  auto cats = by_count(cat_counts);
  for (auto& [ea, l] : orig.linked) {
    lib_bytes += orig.functions.at(ea).size;
    ++lib_counts[l.lib];
  }
  size_t lib_checked = 0, lib_match = 0;
  for (auto& r : results) {
    if (r.kind == "LIBRARY") { ++lib_checked; lib_match += r.status == "MATCH"; }
    if (r.status == "LIBCODE") t.libcode.push_back(&r);
  }
  for (auto* r : t.libcode) {
    std::string sym = r->symbol.value_or("");
    out.print("ERROR " + r->orig + " (" + r->src + ") is linked library code from " + r->lib +
              (sym.empty() ? "" : ", `" + sym + "`") +
              ": remove the definition and reach it as the original does (through the library call or class that uses it); `// " +
              r->kind + ":` is for decompiled code, `// LIBRARY: " + module + " " + r->orig + " <symbol>` for library code");
  }
  out.print("\nannotated " + std::to_string(results.size()) + ": " + std::to_string(t.matched.size()) + " match, " +
            std::to_string(differ) + " do not" + (cats.empty() ? "" : " (" + count_list(cats) + ")"));
  out.print("coverage: " + std::to_string(t.matched.size()) + "/" + std::to_string(universe) + " functions (" +
            percent(t.matched.size(), universe) + "), " + std::to_string(mbytes) + "/" + std::to_string(ubytes) + " bytes (" +
            percent(mbytes, ubytes) + ")");
  out.print("linked library code (not counted): " + std::to_string(orig.linked.size()) + " functions, " +
            std::to_string(lib_bytes) + " bytes" + (lib_counts.empty() ? "" : " (" + count_list(by_count(lib_counts)) + ")") +
            "; LIBRARY annotations " + std::to_string(lib_match) + "/" + std::to_string(lib_checked) + " match");
  t.fields.set("matched", Value::integer(i64(t.matched.size())));
  t.fields.set("universe", Value::integer(i64(universe)));
  t.fields.set("matched_bytes", Value::integer(i64(mbytes)));
  t.fields.set("universe_bytes", Value::integer(i64(ubytes)));
  Value c = Value::object();
  for (auto& [k, v] : cats) c.set(k, Value::integer(v));
  t.fields.set("categories", c);
  t.fields.set("linked_functions", Value::integer(i64(orig.linked.size())));
  t.fields.set("linked_bytes", Value::integer(i64(lib_bytes)));
  return t;
}

bool regression_gate(const std::string& path, const std::set<u64>& matched, const std::vector<Result>& results, bool update, Out& out) {
  std::map<u64, std::string> prev;
  if (file_exists(path)) {
    for (auto& line : read_lines(path)) {
      std::string s = strip(line);
      if (s.empty() || starts_with(line, "#")) continue;
      size_t sp = s.find_first_of(" \t\r\n\v\f");
      u64 va = parse_hex(s.substr(0, sp));
      prev[va] = sp == std::string::npos ? "" : strip(s.substr(sp));
    }
  }
  std::vector<u64> lost;
  for (auto& [v, n] : prev) if (!matched.count(v)) lost.push_back(v);
  for (u64 v : lost) out.print("REGRESSION " + hex(v) + " " + prev[v]);
  for (u64 v : matched) if (!prev.count(v)) out.print("NEW MATCH  " + hex(v));
  if (update) {
    if (!lost.empty()) {
      out.print("refusing --update while regressions exist");
    } else {
      std::map<u64, std::string> names;
      for (auto& r : results) names[r.va] = r.name;
      std::set<u64> all(matched);
      for (auto& [v, n] : prev) all.insert(v);
      std::string text = "# Functions that byte-match. Maintained by verifier --update; --check fails if one regresses.\n";
      for (u64 v : all) {
        auto it = names.find(v);
        text += hex(v) + " " + (it != names.end() ? it->second : prev.count(v) ? prev[v] : "") + "\n";
      }
      std::ofstream(path, std::ios::binary) << text;
    }
  }
  return !lost.empty();
}

}  // namespace

namespace {

// A run's arguments, configuration and phase timer, and its replay record's bookkeeping: the files it hashes (each once),
// and the record's command, stamps and key, worked out only when the record needs them
class RunState {
 public:
  RunState(int argc, char** argv)
      : a(parse_args(argc, argv)), p(Config::load(a.config)), args_(argv + 1, argv + argc), exe_(self_exe()),
        start_(two_seconds_ago()) {
    // every run but --update (which writes the regression list and the name cache) and --show (a look at one function)
    // keeps a record; its key holds the arguments, so a record is only replayed for the same command
    if (!(a.update || a.show)) last_ = path_join(dirname(abspath(a.rebuilt)), LAST_RUN);
  }
  Args a;
  Config p;
  Phases ph;
  bool keeps_record() const { return !last_.empty(); }
  i64 start() const { return start_; }

  // content hashes, each file's once ("" for an absent file); the verifier's own (the replay key, and the key of the
  // cache files only this build can read), and where those files go (nowhere without a cache directory or when this
  // program's path is unknown)
  const std::string& hash_if_present(const std::string& f) {
    auto it = hashes_.find(f);
    if (it == hashes_.end()) it = hashes_.emplace(f, content_hash_file_if_present(f)).first;
    return it->second;
  }
  std::string hash(const std::string& f) {
    std::string h = hash_if_present(f);
    if (h.empty()) throw std::runtime_error("cannot read " + f);
    return h;
  }
  std::string self_hash() { return exe_.empty() ? std::string() : hash(exe_); }
  std::string build_cache(const char* name) const { return exe_.empty() ? std::string() : p.cache_file(name); }

  // the last run's output and exit status when its record replays: the same command and inputs (by the stamps, else by
  // the image's hash and the key), and its report still the --json file
  std::optional<int> replay() {
    if (last_.empty()) return std::nullopt;
    command_ = command_key(args_, p);
    image_stamp_ = file_stamp(a.rebuilt);
    Last rec;
    auto walk_key = [&] { return key_ = key_of(source_files(a)); };
    if (!load_last(last_, command_, image_stamp_, [&] { return stamps_now(); }, [&] { return hash_if_present(a.rebuilt); },
                   walk_key, rec) ||
        !(a.json ? !rec.report_hash.empty() && content_hash_file_if_present(*a.json) == rec.report_hash : rec.report_hash.empty()))
      return std::nullopt;
    std::fputs("verifier inputs unchanged since the last check: its results follow\n", stdout);
    std::fwrite(rec.out.data(), 1, rec.out.size(), stdout);
    std::fflush(stdout);
    // the same contents under new stamps (a file rewritten as it was): the record takes them, for the next run
    if (!rec.by_stamps && !stamps_now().empty())
      save_last(last_, command_, image_stamp_, stamps_, hash_if_present(a.rebuilt), key_, rec.out, rec.report_hash, rec.rc);
    return rec.rc;
  }

  // each source file as the annotations are read: listed for the record's stamps, and its hash for its key
  std::function<void(const ListedFile&, const std::string&)> hashed() {
    if (last_.empty()) return nullptr;
    return [this](const ListedFile& f, const std::string& h) {
      listing_.push_back(f);
      if (key_.empty()) hashes_.emplace(f.path, h);
    };
  }

  // the record of this run (its stamps from the sources as they were read, against the run's start)
  void save_record(const Out& out, const std::string& report, int rc) {
    if (last_.empty()) return;
    if (key_.empty()) {
      std::vector<std::string> sources;
      for (auto& f : listing_) sources.push_back(f.path);
      key_ = key_of(sources);
    }
    save_last(last_, command_, image_stamp_, stamp_key(a, p, exe_, listing_, start_), hash_if_present(a.rebuilt), key_,
              out.text(), a.json ? content_hash(report) : std::string(), rc);
  }

 private:
  std::vector<std::string> args_;
  std::string exe_, last_;
  i64 start_;
  std::unordered_map<std::string, std::string> hashes_;
  std::string command_, image_stamp_, stamps_, key_;
  bool stamped_ = false;
  std::vector<ListedFile> listing_;
  std::string key_of(const std::vector<std::string>& sources) {
    return run_key(a, p, self_hash(), sources, [this](const std::string& f) { return hash_if_present(f); });
  }
  const std::string& stamps_now() {
    if (!stamped_) stamps_ = stamp_key(a, p, exe_);
    stamped_ = true;
    return stamps_;
  }
};

// a file's SHA-256 (the original's configured hash, the name cache's key); throws when it cannot be read
std::string sha256_of(const std::string& f) {
  std::string h = sha256_file_if_present(f);
  if (h.empty()) throw std::runtime_error("cannot read " + f);
  return h;
}

// a destructor's annotation names the scalar deleting destructor when its address is a vtable slot (see pick_destructor)
void pick_destructors(std::vector<Annotation>& anns, const Original& orig, const Rebuilt& reb) {
  std::unordered_set<u64> slots;
  for (auto& [v, ss] : orig.vtables) slots.insert(ss.begin(), ss.end());
  auto has_code = [&](const std::string& n) { return !reb.lookup(n, std::nullopt, true).vas.empty(); };
  for (auto& ann : anns)
    if (ann.flags.dtor) ann.name = pick_destructor(ann.name, slots.count(ann.va) != 0, has_code);
}

// every compared annotation's result, in address order, and the report's results array as they are made (a result
// keeps only what stdout and the summary need)
struct Evaluated {
  std::vector<Result> results;
  std::string report;   // "{ "results": [...]" when there is a report; the totals are added after
};
Evaluated evaluate_all(const std::vector<Annotation>& anns, const Original& orig, const Rebuilt& reb, Pairing& pairing,
                       Comparer& cmp, DiffStore& diffs, const RunState& s, Out& out) {
  std::optional<u64> show;
  if (s.a.show) show = parse_hex(*s.a.show);
  std::vector<const Annotation*> order;
  for (auto& ann : anns) if (is_paired(ann.kind)) order.push_back(&ann);
  std::stable_sort(order.begin(), order.end(), [](auto* x, auto* y) { return x->va < y->va; });
  Evaluated ev;
  ev.results.reserve(order.size());
  if (s.a.json) ev.report = "{\n  \"results\": ";
  for (auto* ann : order) {
    ev.results.push_back(evaluate(*ann, orig, reb, pairing, cmp, s.p.root, show && *show == ann->va, out, true, &diffs));
    if (!s.a.json) continue;
    ev.report += ev.results.size() == 1 ? "[\n    " : ",\n    ";
    write_result(ev.report, ev.results.back(), 2);
    ev.results.back().diff = {};
  }
  if (s.a.json) ev.report += ev.results.empty() ? "[]" : "\n  ]";
  return ev;
}

// VERIFIER_TIMING: how much was decoded, and what the cache directory supplied
void print_cache_stats(const CodeCache& orig_cache, const CodeCache& rebuilt_cache, const CodeStore& orig_store,
                       const DiffStore& diffs) {
  if (!std::getenv("VERIFIER_TIMING")) return;
  auto o = orig_cache.stats(), r = rebuilt_cache.stats();
  std::fprintf(stderr, "decoded: orig %zu functions %zu insns, rebuilt %zu functions %zu insns; sizeof(Insn) %zu\n",
               o.functions, o.insns, r.functions, r.insns, sizeof(Insn));
  std::fprintf(stderr, "original functions from the code store: %zu (decoded %zu)\n", orig_store.stats().hits,
               orig_store.stats().misses);
  std::fprintf(stderr, "DIFF reports from the diff store: %zu (made %zu)\n", diffs.stats().hits, diffs.stats().misses);
}

// stdout after the results' lines: GLOBALs whose bytes differ, and annotations that name nothing
void print_warnings(const std::vector<Annotation>& anns, const std::vector<Ignored>& ignored, const Rebuilt& reb,
                    const Pairing& pairing, Comparer& cmp, const std::string& root, Out& out) {
  auto lookup = [&](const std::string& n) { return reb.lookup(n).vas; };
  for (auto& g : check_globals(anns, lookup, pairing.reb_to_orig, cmp))
    out.print("GLOBAL DIFFERS " + hex(g.ann->va) + " " + g.ann->name + " (" + where_of(g.ann->path, root) + ":" +
              std::to_string(g.ann->line) + "): " + g.problem + "; is the address right?");
  for (auto& ig : ignored)
    out.print("IGNORED ANNOTATION " + where_of(ig.path, root) + ":" + std::to_string(ig.line) + ": `" + ig.text +
              "` names nothing: no definition (FUNCTION/STUB/SYNTHETIC without a name), variable (GLOBAL) or class (VTABLE) "
              "within the next three lines");
}

// the report's totals, and the file written
void finish_report(std::string& report, const Totals& totals, const std::string& path) {
  for (auto& [k, v] : totals.fields.obj) {
    report += ",\n  ";
    json::put_quoted(report, k);
    report += ": ";
    json::put_value(report, v, 1);
  }
  report += "\n}\n";
  std::ofstream(path, std::ios::binary) << report;
}

}  // namespace

int run(int argc, char** argv) {
  RunState s(argc, argv);
  if (auto rc = s.replay()) return *rc;
  if (s.keeps_record()) s.ph.mark("replay key");
  const Args& a = s.a;
  const Config& p = s.p;
  Out out;

  Original orig(p, sha256_of);
  s.ph.mark("original");

  // each source file's annotations kept between runs (with a cache directory): unchanged files are not read again
  std::vector<Ignored> ignored;
  SourceCache sources(s.build_cache("sources-cache.bin"), "verifier " + s.self_hash() + " module " + p.module, s.start());
  auto anns = parse_annotations(a.src, p.module, &ignored, nullptr, &sources, s.hashed());
  sources.save();
  if (std::getenv("VERIFIER_TIMING"))
    std::fprintf(stderr, "source files from the sources cache: %zu (read %zu)\n", sources.stats().hits, sources.stats().misses);
  check_duplicates(anns);
  s.ph.mark("annotations");

  NameCache name_cache(p.names_cache(), "verifier names 1 " + sha256_of(p.undname), p.undname);
  Rebuilt reb(a.rebuilt, a.map, name_cache);
  s.ph.mark("rebuilt+names");

  pick_destructors(anns, orig, reb);
  Pairing pairing(orig, reb, anns);
  // the original's decoded functions kept between runs: the original does not change, so they are all used again (the
  // decoder, the verifier itself, is part of the key); DIFFs' categories and diffs, keyed by the verifier and the
  // original's names (the snapshot's key: not kept when that is not known)
  CodeStore orig_store(s.build_cache("code-original.bin"), orig.img, s.self_hash());
  CodeCache orig_cache(&orig.img, &orig_store), rebuilt_cache(&reb.img);
  DiffStore diff_store(orig.cache_key().empty() ? std::string() : s.build_cache("diff-cache.bin"),
                       "verifier " + s.self_hash() + " names " + orig.cache_key());
  s.ph.mark("pairing");
  Comparer& cmp = pairing.comparer(orig_cache, rebuilt_cache);
  s.ph.mark("prebind votes");

  Evaluated ev = evaluate_all(anns, orig, reb, pairing, cmp, diff_store, s, out);
  s.ph.mark("evaluate");
  print_cache_stats(orig_cache, rebuilt_cache, orig_store, diff_store);
  orig_store.save();
  diff_store.save();
  s.ph.mark("code and diff stores");

  for (auto& r : ev.results) out.print(result_line(r, p.module));
  print_warnings(anns, ignored, reb, pairing, cmp, p.root, out);
  Totals totals = summarize(ev.results, orig, out, p.module);
  s.ph.mark("globals+summary");

  // the names undname gave, for the next run (a check too: until the next --update, every run on this build would run
  // undname for them again)
  if (a.update || name_cache.has_new()) name_cache.save();
  if (a.json) {
    finish_report(ev.report, totals, *a.json);
    s.ph.mark("json");
  }
  int rc = totals.libcode.empty() ? 0 : 1;
  if (a.matched && regression_gate(*a.matched, totals.matched, ev.results, a.update, out)) rc = 1;
  rc = (a.check || a.update) ? rc : 0;
  std::fflush(stdout);
  s.save_record(out, ev.report, rc);
  // everything is written: leave without freeing the run's structures, which takes a tenth of a second for nothing
  std::fflush(nullptr);
  std::_Exit(rc);
}

}  // namespace verifier
