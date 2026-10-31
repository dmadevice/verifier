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

#include "sha256.hpp"

#include <chrono>
#ifdef _WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#undef CONST   // windows.h defines it; Op::CONST is ours
#include <psapi.h>
#else
#include <malloc.h>
#include <sys/resource.h>
#endif

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
                const std::string& root, bool show, Out& out, bool want_diff) {
  u64 ova = ann.va;
  Result rec;
  rec.va = ova;
  rec.orig = hex(ova);
  rec.name = ann.name;
  rec.kind = ann.kind;
  rec.src = where_of(ann.path, root) + ":" + std::to_string(ann.line);
  auto lk = reb.lookup(ann.name, sig_flag(ann.flags), true);
  rec.overloads = reb.overloads_of(ann.name);
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
  if (!probs.empty()) rec.category = same ? probs[0].first : classify(ot, rt);
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
    if (want_diff) {
      auto offsets = [](const Code& c) { std::vector<u32> v; for (auto& l : c.insns) v.push_back(l.off); return v; };
      rec.diff = insn_diff(offsets(oc), offsets(rc), ot, rt, cmp.names);
    }
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

std::string self_exe() {
#ifdef _WIN32
  wchar_t buf[32768];
  DWORD n = GetModuleFileNameW(nullptr, buf, 32768);
  return std::filesystem::path(std::wstring(buf, n)).string();
#else
  std::error_code ec;
  return std::filesystem::read_symlink("/proc/self/exe", ec).string();
#endif
}

[[noreturn]] void usage(const std::string& err) {
  std::fprintf(stderr,
               "usage: verifier [--config FILE] --rebuilt REBUILT --map MAP --src SRC [SRC ...] [--matched MATCHED]\n"
               "                  [--check] [--update] [--json JSON] [--show SHOW]\n"
               "verifier: error: %s\n", err.c_str());
  std::exit(2);
}

Args parse_args(int argc, char** argv) {
  Args a;
  bool have_rebuilt = false, have_map = false;
  for (int i = 1; i < argc; ++i) {
    std::string s = argv[i];
    auto value = [&](const char* opt) -> std::string {
      if (i + 1 >= argc || (argv[i + 1][0] == '-' && argv[i + 1][1])) usage(std::string("argument ") + opt + ": expected one argument");
      return argv[++i];
    };
    if (s == "--config") { a.config = value("--config"); }
    else if (s == "--rebuilt") { a.rebuilt = value("--rebuilt"); have_rebuilt = true; }
    else if (s == "--map") { a.map = value("--map"); have_map = true; }
    else if (s == "--matched") a.matched = value("--matched");
    else if (s == "--json") a.json = value("--json");
    else if (s == "--show") a.show = value("--show");
    else if (s == "--check") a.check = true;
    else if (s == "--update") a.update = true;
    else if (s == "--src") {
      a.src.clear();
      while (i + 1 < argc && !(argv[i + 1][0] == '-' && argv[i + 1][1])) a.src.push_back(argv[++i]);
      if (a.src.empty()) usage("argument --src: expected at least one argument");
    } else {
      usage("unrecognized arguments: " + s);
    }
  }
  std::vector<std::string> missing;
  if (!have_rebuilt) missing.push_back("--rebuilt");
  if (!have_map) missing.push_back("--map");
  if (a.src.empty()) missing.push_back("--src");
  if (!missing.empty()) usage("the following arguments are required: " + join(missing, ", "));
  return a;
}

// VERIFIER_TIMING=1: each phase's wall time and the peak RSS so far, on stderr
class Phases {
 public:
  Phases() : on_(std::getenv("VERIFIER_TIMING") != nullptr), t_(std::chrono::steady_clock::now()) {}
  void mark(const char* what) {
    if (!on_) return;
    auto now = std::chrono::steady_clock::now();
    double ms = std::chrono::duration<double, std::milli>(now - t_).count();
    t_ = now;
    long rss = 0, heap = 0;
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS_EX pmc{};   // peak working set; private commit in use
    if (GetProcessMemoryInfo(GetCurrentProcess(), reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof pmc)) {
      rss = long(pmc.PeakWorkingSetSize >> 20);
      heap = long(pmc.PrivateUsage >> 20);
    }
#else
    rusage ru{};
    getrusage(RUSAGE_SELF, &ru);
    rss = ru.ru_maxrss / 1024;
#ifdef __GLIBC__
    heap = long(mallinfo2().uordblks >> 20);
#endif
#endif
    std::fprintf(stderr, "%-24s %8.1f ms  peak %ld MB  heap in use %ld MB\n", what, ms, rss, heap);
  }

 private:
  bool on_;
  std::chrono::steady_clock::time_point t_;
};

// -- replay: the last run's output, report and exit status, keyed by everything it read ------------------------

constexpr const char* LAST_RUN = "verifier-last.txt";   // beside the rebuilt image

// a key's field: its length, then its bytes (no two lists of fields hash alike)
void add_field(Sha256& h, std::string_view data) {
  u64 n = data.size();
  char len[8];
  std::memcpy(len, &n, 8);
  h.update(std::string_view(len, 8));
  h.update(data);
}

std::vector<std::string> source_files(const Args& a) {   // the files under --src, in list_files order
  std::vector<std::string> out;
  for (auto& top : a.src) for (auto& f : list_files(top)) out.push_back(std::move(f.path));
  return out;
}

}  // namespace

std::string run_key(const Args& a, const Config& p, const std::string& verifier, const std::vector<std::string>& sources,
                    const std::function<std::string(const std::string&)>& hash) {
  Sha256 h;
  auto add = [&](std::string_view data) { add_field(h, data); };
  add("verifier 4");
  add(verifier);
  std::vector<std::string> files{a.rebuilt, a.map, a.matched.value_or(""), p.undname};
  // the original and the exports: with a cache a run reads them only through the snapshot, so its key stands for them
  if (p.cache_dir.empty()) for (auto* f : p.snapshot_inputs()) files.push_back(*f);
  else add(Original::snapshot_key(p));
  files.insert(files.end(), sources.begin(), sources.end());
  for (auto& f : files) {
    add(f);
    std::string digest = f.empty() ? "" : hash(f);
    add(digest.empty() ? std::string("\0absent", 7) : digest);
  }
  return h.hexdigest();
}

std::string run_key(const Args& a, const Config& p, const std::string& verifier) {
  return run_key(a, p, verifier, source_files(a), sha256_file_if_present);
}

i64 two_seconds_ago() {
  namespace fs = std::filesystem;
  return i64((fs::file_time_type::clock::now() - std::chrono::seconds(2)).time_since_epoch().count());
}

std::string stamp_key(const Args& a, const Config& p, const std::string& exe) {
  std::vector<ListedFile> sources;
  for (auto& top : a.src)
    for (auto& f : list_files(top)) sources.push_back(std::move(f));
  return stamp_key(a, p, exe, sources, two_seconds_ago());
}

std::string stamp_key(const Args& a, const Config& p, const std::string& exe, const std::vector<ListedFile>& sources,
                      i64 recent) {
  Sha256 h;
  auto add = [&](std::string_view data) { add_field(h, data); };
  bool racy = false;
  auto stamp = [&](const std::string& f) {
    i64 t = std::numeric_limits<i64>::min();   // none for an absent file (the clock's epoch may make times negative)
    add(f.empty() ? "" : file_stamp(f, &t));
    racy |= t >= recent;
  };
  add("verifier stamps 2");
  stamp(exe);
  for (auto* f : {&a.rebuilt, &a.map, &p.undname}) stamp(*f);
  stamp(a.matched.value_or(""));
  if (p.cache_dir.empty())
    for (auto* f : p.snapshot_inputs()) stamp(*f);
  else
    add(Original::snapshot_key(p));
  for (auto& f : sources) {
    add(f.path);
    add(std::to_string(f.size) + "\t" + std::to_string(f.time));
    racy |= f.time >= recent;
  }
  return racy ? "" : h.hexdigest();
}

std::string command_key(const std::vector<std::string>& args, const Config& p) {
  Sha256 h;
  for (auto& s : args) add_field(h, s);
  add_field(h, p.root);
  add_field(h, sha256_file_if_present(p.file));
  return h.hexdigest();
}

namespace {

// the record: a version line, the command, the rebuilt image's stamp, all the inputs' stamps ("-" for none), the
// rebuilt image's SHA-256, the key, the exit status, then stdout and the report, each after its length. Checked in
// that order: another command does not replay; the stamps, from metadata alone (all of them only when the image's
// agrees: after a link it does not); when they differ, the image's hash (a replay needs the same image), and only when
// that agrees the key, which hashes every input.
struct Last {
  std::string out, report;
  int rc = 0;
  bool by_stamps = false;   // replayed by the stamps (else by the contents: the record's stamps are stale)
};
bool load_last(const std::string& path, const std::string& command, const std::string& image_stamp,
               const std::function<std::string()>& stamps, const std::function<std::string()>& image,
               const std::function<std::string()>& key, Last& last) {
  if (!file_exists(path)) return false;
  std::unique_ptr<MappedFile> file;   // released before save_last renames a new record over it
  try { file = std::make_unique<MappedFile>(path); } catch (...) { return false; }
  std::string_view d = file->view();
  size_t p = 0;
  auto line = [&](std::string_view& v) {
    size_t e = d.find('\n', p);
    if (e == std::string_view::npos) return false;
    v = d.substr(p, e - p);
    p = e + 1;
    return true;
  };
  std::string_view version, rec_command, rec_image_stamp, rec_stamps, rec_image, rec_key;
  if (!line(version) || version != "verifier-last 6" || !line(rec_command) || rec_command != command ||
      !line(rec_image_stamp) || !line(rec_stamps) || !line(rec_image) || !line(rec_key))
    return false;
  last.by_stamps = rec_image_stamp == image_stamp && rec_stamps != "-" && rec_stamps == stamps();
  if (!last.by_stamps && (rec_image != image() || rec_key != key())) return false;
  auto num = [&](u64& v) {
    std::string_view s;
    if (!line(s)) return false;
    v = std::strtoull(std::string(s).c_str(), nullptr, 10);
    return true;
  };
  u64 r, no, nr;
  if (!num(r) || !num(no) || p + no > d.size()) return false;
  last.out = std::string(d.substr(p, no));
  p += no;
  if (!num(nr) || p + nr != d.size()) return false;
  last.report = std::string(d.substr(p, nr));
  last.rc = int(r);
  return true;
}

void save_last(const std::string& path, const std::string& command, const std::string& image_stamp, const std::string& stamps,
               const std::string& image, const std::string& key, const std::string& out, const std::string& report, int rc) {
  write_file_atomic(path, "verifier-last 6\n" + command + "\n" + image_stamp + "\n" + (stamps.empty() ? "-" : stamps) + "\n" +
                              image + "\n" + key + "\n" +
                              std::to_string(rc) + "\n" + std::to_string(out.size()) + "\n" + out +
                              std::to_string(report.size()) + "\n" + report);
}

}  // namespace

int run(int argc, char** argv) {
  Args a = parse_args(argc, argv);
  Config p = Config::load(a.config);
  std::string last;
  // every run but --update (which writes the regression list and the name cache) and --show (a look at one function)
  // keeps a record; its key holds the arguments, so a record is only replayed for the same command
  if (!(a.update || a.show)) last = path_join(dirname(abspath(a.rebuilt)), LAST_RUN);
  Phases ph;
  // each file is hashed once: the replay key, the original's check and the name cache's key share them
  std::unordered_map<std::string, std::string> hashes;   // "" for an absent file
  auto hash_if_present = [&](const std::string& f) {
    auto it = hashes.find(f);
    if (it == hashes.end()) it = hashes.emplace(f, sha256_file_if_present(f)).first;
    return it->second;
  };
  auto hash = [&](const std::string& f) {
    std::string h = hash_if_present(f);
    if (h.empty()) throw std::runtime_error("cannot read " + f);
    return h;
  };
  std::vector<std::string> args(argv + 1, argv + argc);
  std::string exe = self_exe();
  auto key_of = [&](const std::vector<std::string>& sources) {
    return run_key(a, p, exe.empty() ? "" : hash(exe), sources, hash_if_present);
  };
  // computed before the run only when the record needs them: the stamps when its image has this one's, the key when
  // the stamps differ and its image has this one's hash. The record a run writes takes its stamps (and the key, unless
  // it came first) from the sources as they are parsed, against the run's start
  std::string command, image_stamp, stamps, key;
  bool stamped = false;
  i64 start = two_seconds_ago();
  if (!last.empty()) {
    command = command_key(args, p);
    image_stamp = file_stamp(a.rebuilt);
    auto stamps_now = [&] {
      if (!stamped) stamps = stamp_key(a, p, exe);
      stamped = true;
      return stamps;
    };
    auto walk_key = [&] { return key = key_of(source_files(a)); };
    Last rec;
    if (load_last(last, command, image_stamp, stamps_now, [&] { return hash_if_present(a.rebuilt); }, walk_key, rec)) {
      std::fputs("verifier inputs unchanged since the last check: its results follow\n", stdout);
      std::fwrite(rec.out.data(), 1, rec.out.size(), stdout);
      if (a.json) std::ofstream(*a.json, std::ios::binary) << rec.report;
      std::fflush(stdout);
      // the same contents under new stamps (a file rewritten as it was): the record takes them, for the next run
      if (!rec.by_stamps && !stamps_now().empty())
        save_last(last, command, image_stamp, stamps, hash_if_present(a.rebuilt), key, rec.out, rec.report, rec.rc);
      return rec.rc;
    }
  }
  if (!last.empty()) ph.mark("replay key");
  Out out;
  Original orig(p, hash);
  ph.mark("original");
  std::vector<Ignored> ignored;
  std::vector<ListedFile> listing;
  std::function<void(const ListedFile&, std::string_view)> seen;
  if (!last.empty())
    seen = [&](const ListedFile& f, std::string_view data) {
      listing.push_back(f);
      if (key.empty()) hashes.emplace(f.path, sha256_hex(data));
    };
  auto anns = parse_annotations(a.src, p.module, &ignored, seen);
  check_duplicates(anns);
  ph.mark("annotations");
  NameCache name_cache(p.names_cache(), "verifier names 1 " + hash(p.undname), p.undname);
  Rebuilt reb(a.rebuilt, a.map, name_cache);
  ph.mark("rebuilt+names");
  std::unordered_set<u64> slots;
  for (auto& [v, ss] : orig.vtables) slots.insert(ss.begin(), ss.end());
  auto has_code = [&](const std::string& n) { return !reb.lookup(n, std::nullopt, true).vas.empty(); };
  for (auto& ann : anns)
    if (ann.flags.dtor) ann.name = pick_destructor(ann.name, slots.count(ann.va) != 0, has_code);
  Pairing pairing(orig, reb, anns);
  CodeCache orig_cache(&orig.img), rebuilt_cache(&reb.img);
  ph.mark("pairing");
  Comparer& cmp = pairing.comparer(orig_cache, rebuilt_cache);
  ph.mark("prebind votes");

  std::optional<u64> show;
  if (a.show) show = parse_hex(*a.show);
  std::vector<const Annotation*> order;
  for (auto& ann : anns) if (is_paired(ann.kind)) order.push_back(&ann);
  std::stable_sort(order.begin(), order.end(), [](auto* x, auto* y) { return x->va < y->va; });
  // the report's results are written as they are made: a result keeps what stdout and the summary need
  std::vector<Result> results;
  results.reserve(order.size());
  std::string report;
  if (a.json) report = "{\n  \"results\": ";
  for (auto* ann : order) {
    results.push_back(evaluate(*ann, orig, reb, pairing, cmp, p.root, show && *show == ann->va, out));
    if (!a.json) continue;
    report += results.size() == 1 ? "[\n    " : ",\n    ";
    write_result(report, results.back(), 2);
    results.back().diff = {};
  }
  if (a.json) report += results.empty() ? "[]" : "\n  ]";
  ph.mark("evaluate");
  if (std::getenv("VERIFIER_TIMING")) {
    auto o = orig_cache.stats(), r = rebuilt_cache.stats();
    std::fprintf(stderr, "decoded: orig %zu functions %zu insns, rebuilt %zu functions %zu insns; sizeof(Insn) %zu\n",
                 o.functions, o.insns, r.functions, r.insns, sizeof(Insn));
  }
  for (auto& r : results) out.print(result_line(r, p.module));
  auto lookup = [&](const std::string& n) { return reb.lookup(n).vas; };
  for (auto& g : check_globals(anns, lookup, pairing.reb_to_orig, cmp))
    out.print("GLOBAL DIFFERS " + hex(g.ann->va) + " " + g.ann->name + " (" + where_of(g.ann->path, p.root) + ":" +
              std::to_string(g.ann->line) + "): " + g.problem + "; is the address right?");
  for (auto& ig : ignored)
    out.print("IGNORED ANNOTATION " + where_of(ig.path, p.root) + ":" + std::to_string(ig.line) + ": `" + ig.text +
              "` names nothing: no definition (FUNCTION/STUB/SYNTHETIC without a name), variable (GLOBAL) or class (VTABLE) "
              "within the next three lines");
  Totals totals = summarize(results, orig, out, p.module);
  ph.mark("globals+summary");

  // the names undname gave, for the next run (a check too: until the next --update, every run on this build would run
  // undname for them again)
  if (a.update || name_cache.has_new()) name_cache.save();
  if (a.json) {
    for (auto& [k, v] : totals.fields.obj) {
      report += ",\n  ";
      json::put_quoted(report, k);
      report += ": ";
      json::put_value(report, v, 1);
    }
    report += "\n}\n";
    std::ofstream(*a.json, std::ios::binary) << report;
    ph.mark("json");
  }
  int rc = totals.libcode.empty() ? 0 : 1;
  if (a.matched && regression_gate(*a.matched, totals.matched, results, a.update, out)) rc = 1;
  rc = (a.check || a.update) ? rc : 0;
  std::fflush(stdout);
  if (!last.empty()) {
    if (key.empty()) {
      std::vector<std::string> sources;
      for (auto& f : listing) sources.push_back(f.path);
      key = key_of(sources);
    }
    save_last(last, command, image_stamp, stamp_key(a, p, exe, listing, start), hash_if_present(a.rebuilt), key,
              out.text(), report, rc);
  }
  // everything is written: leave without freeing the run's structures, which takes a tenth of a second for nothing
  std::fflush(nullptr);
  std::_Exit(rc);
}

}  // namespace verifier
