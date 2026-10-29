#include "verify.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>

#include "sha256.hpp"

#include <chrono>
#ifdef _WIN32
#include <windows.h>
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

Value str_list(std::vector<std::string> v) {
  Value a = Value::array();
  a.arr.reserve(v.size());
  for (auto& s : v) a.push(Value::str(std::move(s)));
  return a;
}

// a source path as the report gives it (relative to the root); many annotations share a file
const std::string& where_of(const std::string& path, const std::string& root) {
  static std::unordered_map<std::string, std::string> memo;
  std::string key = root + '\0' + path;
  auto it = memo.find(key);
  if (it == memo.end()) it = memo.emplace(std::move(key), relpath(path, root)).first;
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
      c.bytes = O.bytes(o.ops[z].key.va, i64(r.ops[z].bytes.size()));
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

json::Value evaluate(const Annotation& ann, const Original& orig, const Rebuilt& reb, Pairing& pairing, Comparer& cmp,
                     const std::string& root, bool show, Out& out, bool want_diff) {
  u64 ova = ann.va;
  Value rec = Value::object();
  rec.set("orig", Value::str(hex(ova)));
  rec.set("name", Value::str(ann.name));
  rec.set("kind", Value::str(ann.kind));
  rec.set("src", Value::str(where_of(ann.path, root) + ":" + std::to_string(ann.line)));
  auto lk = reb.lookup(ann.name, sig_flag(ann.flags), true);
  auto overloads = reb.overloads_of(ann.name);
  if (overloads.size() > 1) rec.set("overloads", str_list(overloads));
  if (!orig.functions.count(ova)) { rec.set("status", Value::str("BADADDR")); return rec; }
  if (is_counted(ann.kind) && orig.linked.count(ova)) {
    rec.set("status", Value::str("LIBCODE"));
    auto& l = orig.linked.at(ova);
    Value lib = Value::array();
    lib.push(Value::str(l.lib));
    lib.push(l.has_symbol ? Value::str(l.symbol) : Value::null());
    rec.set("library", lib);
    return rec;
  }
  if (lk.vas.empty() || lk.nhits > 1) { rec.set("status", Value::str(lk.vas.empty() ? "MISSING" : "AMBIGUOUS")); return rec; }
  rec.set("name", Value::str(lk.qname));
  u64 rva = lk.vas[0];
  u64 oend = orig.extent(ova), rend = reb.extent(rva);
  Problems probs = cmp.function(ova, oend, rva, rend);
  const FnMemo* m = cmp.memo_fn.find({ova, rva});
  const Code &oc = *m->oc, &rc = *m->rc;
  std::function<Key(u64)> resolve = [&](u64 t) { return pairing.resolve(t); };
  std::set<std::string> unresolved;
  bool same = same_tokens(oc, rc, ova, oend, rva, rend, orig.img, reb.img, resolve, unresolved);
  std::vector<Insn> oi, ri;   // decoded again, with their tokens, only when the report shows instructions
  Toks ot, rt;
  if (!same || show) {
    oi = oc.decoded();
    ri = rc.decoded();
    ot = symbolise(oi, ova, oend, by_va(), orig.img, false);
    rt = symbolise(ri, rva, rend, resolve, reb.img, true);
    for (size_t k = 0; k < std::min(ot.size(), rt.size()); ++k) const_by_value(ot[k], rt[k], orig.img);
    unresolved.clear();
    for (auto& t : rt) add_unresolved(t, unresolved);
    same = ot == rt;
  }
  Value category = probs.empty() ? Value::null() : Value::str(same ? probs[0].first : classify(ot, rt));
  rec.set("osize", Value::integer(i64(oend - ova)));
  rec.set("rsize", Value::integer(i64(rend - rva)));
  rec.set("status", Value::str(probs.empty() ? "MATCH" : "DIFF"));
  rec.set("category", category);
  rec.set("unresolved", str_list(std::vector<std::string>(unresolved.begin(), unresolved.end())));
  std::vector<std::string> ps;
  for (size_t i = 0; i < probs.size() && i < 8; ++i) ps.push_back(probs[i].first + ": " + probs[i].second);
  rec.set("problems", str_list(std::move(ps)));
  if (!same) {
    for (size_t k = 0; k < std::min(ot.size(), rt.size()); ++k) {
      if (ot[k] == rt[k]) continue;
      Value fd = Value::object();
      fd.set("index", Value::integer(i64(k)));
      fd.set("orig", Value::str(oi[k].mnemonic + " " + oi[k].op_str()));
      fd.set("rebuilt", Value::str(ri[k].mnemonic + " " + ri[k].op_str()));
      rec.set("first_diff", fd);
      break;
    }
    rec.set("diff", want_diff ? str_list(insn_diff(oi, ri, ot, rt, cmp.names)) : Value::array());
  }
  if (show) {
    out.print("--- " + lk.qname + "  orig " + std::to_string(oend - ova) + "B | rebuilt " + std::to_string(rend - rva) + "B  " +
              (probs.empty() ? "MATCH" : "DIFF"));
    for (auto& [c, d] : probs) out.print("  problem " + c + ": " + d);
    for (size_t k = 0; k < std::max(oi.size(), ri.size()); ++k) {
      std::string x = k < oi.size() ? oi[k].mnemonic + " " + oi[k].op_str() : "";
      std::string y = k < ri.size() ? ri[k].mnemonic + " " + ri[k].op_str() : "";
      bool eq = k < ot.size() && k < rt.size() && ot[k] == rt[k];
      out.print(std::string(eq ? " " : "*") + " " + pad_right(x, 48) + " | " + y);
    }
  }
  return rec;
}

std::string result_line(const Value& r, const std::string& module) {
  auto field = [&](const char* k) -> std::string {
    const Value* v = r.get(k);
    if (!v) return "-";
    return v->type == Value::Int ? std::to_string(v->i) : v->s;
  };
  const Value* cat = r.get("category");
  std::string line = pad_right(r["status"].s, 9) + " " + r["orig"].s + " " + pad_left(field("osize"), 5) + "/" +
                     pad_right(field("rsize"), 5) + " " + pad_right(cat && cat->type == Value::String ? cat->s : "", 12) + " " +
                     r["name"].s;
  auto items = [&](const char* k) -> const Value* {   // a non-empty array or object field
    const Value* v = r.get(k);
    return v && (!v->arr.empty() || !v->obj.empty()) ? v : nullptr;
  };
  const Value* fd = items("first_diff");
  const Value* pr = items("problems");
  if (fd) {
    line += "\n            @" + std::to_string((*fd)["index"].i) + ": orig `" + (*fd)["orig"].s + "` | rebuilt `" + (*fd)["rebuilt"].s + "`";
  } else if (pr) {
    line += "\n            " + head_chars(pr->arr[0].s, 160);
  }
  const Value* un = items("unresolved");
  if (un) {
    std::vector<std::string> xs;
    for (auto& x : un->arr) xs.push_back(head_chars(x.s, 90));
    line += "\n            unresolved: " + join(xs, ", ");
  }
  const Value* ov = items("overloads");
  if (ov && r["status"].s != "MATCH") {
    std::vector<std::string> xs;
    for (auto& x : ov->arr) xs.push_back(x.s);
    line += "\n            overloads: " + head_chars(join(xs, " "), 200) + " (pick one: `// FUNCTION: " + module + " 0x... (<params>)`)";
  }
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
  std::vector<const Value*> libcode;
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

Totals summarize(const std::vector<Value>& results, const Original& orig, Out& out, const std::string& module) {
  Totals t;
  for (auto& r : results)
    if (r["status"].s == "MATCH" && is_counted(r["kind"].s)) t.matched.insert(parse_hex(r["orig"].s));
  std::pair<u64, u64> funclets{0, 0};
  if (auto it = orig.img.pogo.find(".text$x"); it != orig.img.pogo.end()) funclets = it->second;
  size_t universe = 0;
  u64 ubytes = 0, mbytes = 0, lib_bytes = 0;
  for (u64 ea : orig.function_order) {
    auto& f = orig.functions.at(ea);
    if (f.lib || f.thunk || orig.linked.count(ea) || (funclets.first <= ea && ea < funclets.second)) continue;
    ++universe;
    ubytes += f.size;
  }
  for (u64 v : t.matched) mbytes += orig.functions.at(v).size;
  std::map<std::string, i64> cat_counts, lib_counts;
  size_t differ = 0;
  for (auto& r : results) {
    if (r["status"].s == "MATCH") continue;
    ++differ;
    const Value* c = r.get("category");
    ++cat_counts[c && c->type == Value::String ? c->s : r["status"].s];
  }
  auto cats = by_count(cat_counts);
  for (auto& [ea, l] : orig.linked) {
    lib_bytes += orig.functions.at(ea).size;
    ++lib_counts[l.lib];
  }
  size_t lib_checked = 0, lib_match = 0;
  for (auto& r : results) {
    if (r["kind"].s == "LIBRARY") { ++lib_checked; lib_match += r["status"].s == "MATCH"; }
    if (r["status"].s == "LIBCODE") t.libcode.push_back(&r);
  }
  for (auto* r : t.libcode) {
    auto& lib = (*r)["library"];
    std::string sym = lib.arr[1].is_null() ? "" : lib.arr[1].s;
    out.print("ERROR " + (*r)["orig"].s + " (" + (*r)["src"].s + ") is linked library code from " + lib.arr[0].s +
              (sym.empty() ? "" : ", `" + sym + "`") +
              ": remove the definition and reach it as the original does (through the library call or class that uses it); `// " +
              (*r)["kind"].s + ":` is for decompiled code, `// LIBRARY: " + module + " " + (*r)["orig"].s + " <symbol>` for library code");
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

bool regression_gate(const std::string& path, const std::set<u64>& matched, const std::vector<Value>& results, bool update, Out& out) {
  std::map<u64, std::string> prev;
  if (file_exists(path)) {
    for (auto& line : read_lines(path)) {
      if (strip(line).empty() || starts_with(line, "#")) continue;
      std::string s = strip(line);
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
      for (auto& r : results) names[parse_hex(r["orig"].s)] = r["name"].s;
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
    else if (s == "--matched") { a.matched = value("--matched"); a.has_matched = true; }
    else if (s == "--json") { a.json = value("--json"); a.has_json = true; }
    else if (s == "--show") { a.show = value("--show"); a.has_show = true; }
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
#ifndef _WIN32
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

// -- --check replay: the last --check run's output, report and exit status, keyed by everything it read ------

constexpr const char* LAST_RUN = "verifier-last.txt";

}  // namespace

std::string run_key(const std::vector<std::string>& args, const Args& a, const Config& p, const std::string& verifier) {
  Sha256 h;
  auto add = [&](const std::string& data) {
    u64 n = data.size();
    char len[8];
    std::memcpy(len, &n, 8);
    h.update(std::string_view(len, 8));
    h.update(data);
  };
  add("verifier 1");
  add(verifier);
  add(p.root);
  for (auto& s : args) add(s);
  std::vector<std::string> files{a.rebuilt, a.map, a.has_matched ? a.matched : "", p.file, p.original, p.functions, p.vtables,
                                 p.data_items, p.data_names, p.library_matches, p.library_functions, p.symbols, p.undname};
  for (auto& top : a.src) for (auto& f : walk_files(top)) files.push_back(f);
  for (auto& f : files) {
    add(f);
    if (!f.empty() && file_exists(f)) add(read_file(f));
    else add(std::string("\0absent", 7));
  }
  return h.hexdigest();
}

namespace {

bool load_last(const std::string& path, const std::string& key, std::string& out, std::string& report, int& rc) {
  if (!file_exists(path)) return false;
  std::string d;
  try { d = read_file(path); } catch (...) { return false; }
  std::string head = "verifier-last 1\n" + key + "\n";
  if (d.compare(0, head.size(), head) != 0) return false;
  size_t p = head.size();
  auto num = [&](u64& v) {
    size_t e = d.find('\n', p);
    if (e == std::string::npos) return false;
    v = std::strtoull(d.substr(p, e - p).c_str(), nullptr, 10);
    p = e + 1;
    return true;
  };
  u64 r, no, nr;
  if (!num(r) || !num(no) || p + no > d.size()) return false;
  out = d.substr(p, no);
  p += no;
  if (!num(nr) || p + nr != d.size()) return false;
  report = d.substr(p, nr);
  rc = int(r);
  return true;
}

void save_last(const std::string& path, const std::string& key, const std::string& out, const std::string& report, int rc) {
  std::string tmp = path + ".tmp";
  {
    std::ofstream f(tmp, std::ios::binary);
    f << "verifier-last 1\n" << key << "\n" << rc << "\n" << out.size() << "\n" << out << report.size() << "\n" << report;
    if (!f) return;
  }
  std::error_code ec;
  std::filesystem::rename(tmp, path, ec);
  if (ec) std::filesystem::remove(tmp, ec);
}

}  // namespace

int run(int argc, char** argv) {
  Args a = parse_args(argc, argv);
  Config p = Config::load(a.config);
  std::string last;
  if (a.has_json && a.check && !(a.update || a.has_show)) last = path_join(dirname(abspath(a.json)), LAST_RUN);
  std::string key;
  if (!last.empty()) {
    std::string exe = self_exe();
    key = run_key(std::vector<std::string>(argv + 1, argv + argc), a, p, exe.empty() ? "" : sha256_file(exe));
    std::string out, report;
    int rc;
    if (load_last(last, key, out, report, rc)) {
      std::fputs("verifier inputs unchanged since the last check: its results follow\n", stdout);
      std::fwrite(out.data(), 1, out.size(), stdout);
      std::ofstream(a.json, std::ios::binary) << report;
      std::fflush(stdout);
      return rc;
    }
  }
  Out out;
  Phases ph;
  Original orig(p);
  ph.mark("original");
  std::vector<Ignored> ignored;
  auto anns = parse_annotations(a.src, p.module, &ignored);
  check_duplicates(anns);
  ph.mark("annotations");
  NameCache name_cache(p.names_cache(), "verifier names 1 " + sha256_file(p.undname), p.undname);
  Rebuilt reb(a.rebuilt, a.map, name_cache);
  ph.mark("rebuilt+names");
  std::unordered_set<u64> slots;
  for (auto& [v, ss] : orig.vtables) slots.insert(ss.begin(), ss.end());
  auto has_code = [&](const std::string& n) { return !reb.lookup(n, std::nullopt, true).vas.empty(); };
  for (auto& ann : anns)
    if (ann.flags.count("DTOR")) ann.name = pick_destructor(ann.name, slots.count(ann.va) != 0, has_code);
  Pairing pairing(orig, reb, anns);
  CodeCache orig_cache(&orig.img), rebuilt_cache(&reb.img);
  ph.mark("pairing");
  Comparer& cmp = pairing.comparer(orig_cache, rebuilt_cache);
  ph.mark("prebind votes");

  std::optional<u64> show;
  if (a.has_show) show = parse_hex(a.show);
  std::vector<const Annotation*> order;
  for (auto& ann : anns) if (is_paired(ann.kind)) order.push_back(&ann);
  std::stable_sort(order.begin(), order.end(), [](auto* x, auto* y) { return x->va < y->va; });
  std::vector<Value> results;
  results.reserve(order.size());
  for (auto* ann : order) results.push_back(evaluate(*ann, orig, reb, pairing, cmp, p.root, show && *show == ann->va, out));
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

  if (a.update) name_cache.save();
  std::string report;
  if (a.has_json) {
    Value doc = Value::object();
    Value rs = Value::array();
    rs.arr = std::move(results);
    doc.set("results", std::move(rs));
    for (auto& [k, v] : totals.fields.obj) doc.set(k, v);
    report = json::dump(doc);
    std::ofstream(a.json, std::ios::binary) << report;
    results = std::move(doc.obj[0].second.arr);
    ph.mark("json");
  }
  int rc = totals.libcode.empty() ? 0 : 1;
  if (a.has_matched && regression_gate(a.matched, totals.matched, results, a.update, out)) rc = 1;
  rc = (a.check || a.update) ? rc : 0;
  std::fflush(stdout);
  if (!last.empty()) save_last(last, key, out.text(), report, rc);
  // everything is written: leave without freeing the run's structures, which takes a tenth of a second for nothing
  std::fflush(nullptr);
  std::_Exit(rc);
}

}  // namespace verifier
