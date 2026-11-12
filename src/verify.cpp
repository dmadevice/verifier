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
#include "timing.hpp"

namespace verifier {

using json::Value;

std::vector<GlobalRoot> global_roots(const std::vector<Annotation>& anns,
                                     const std::function<std::vector<u64>(const std::string&)>& lookup,
                                     const std::function<std::optional<u64>(u64)>& orig_of, const Image& O,
                                     const Image& R) {
  std::vector<const Annotation*> sorted;
  for (auto& a : anns) sorted.push_back(&a);
  std::stable_sort(sorted.begin(), sorted.end(), [](auto* x, auto* y) { return x->va < y->va; });
  std::vector<GlobalRoot> out;
  for (auto* a : sorted) {
    u64 va = a->va;
    if (a->kind != Kind::Global || !O.flags(va) || O.writable(va) || O.executable(va)) continue;
    for (u64 rva : lookup(a->name))
      if (orig_of(rva) == va && !R.writable(rva) && !R.executable(rva)) out.push_back({a, rva});
  }
  return out;
}

std::vector<std::pair<u64, u64>> data_pairs(const std::vector<GlobalRoot>& roots) {
  std::vector<std::pair<u64, u64>> out;
  for (auto& g : roots) out.emplace_back(g.ann->va, g.rva);
  return out;
}

std::vector<GlobalDiff> check_globals(const std::vector<GlobalRoot>& roots, Comparer& cmp) {
  std::vector<GlobalDiff> out;
  for (auto& g : roots)
    if (auto p = cmp.judge_rodata(g.ann->va, g.rva)) out.push_back({g.ann, p->detail});
  return out;
}

namespace {

// what the summary and the regression gate read of a result once its line and report entry are made
struct Outcome {
  u64 va;
  Kind kind;  // the annotation's
  Status status;
  std::optional<Category> category;
  std::string name;
};

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

std::string count_list(const std::vector<std::pair<std::string, i64>>& v) {  // "a 3, b 1"
  std::vector<std::string> parts;
  for (auto& [k, n] : v) parts.push_back(k + " " + std::to_string(n));
  return join(parts, ", ");
}

// `libcode`: the LIBCODE results (in full: their errors name where they are)
Totals summarize(const std::vector<Outcome>& results, const std::vector<Result>& libcode, const Original& orig,
                 Out& out, const std::string& module) {
  Totals t;
  for (auto& r : results)
    if (r.status == Status::Match && is_counted(r.kind)) t.matched.insert(r.va);
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
    if (r.status == Status::Match) continue;
    ++differ;
    ++cat_counts[std::string(r.category ? category_name(*r.category) : status_name(r.status))];
  }
  auto cats = by_count(cat_counts);
  for (auto& [ea, l] : orig.linked) {
    lib_bytes += orig.functions.at(ea).size;
    ++lib_counts[l.lib];
  }
  size_t lib_checked = 0, lib_match = 0;
  for (auto& r : results) {
    if (r.kind == Kind::Library) {
      ++lib_checked;
      lib_match += r.status == Status::Match;
    }
  }
  for (auto& r : libcode) t.libcode.push_back(&r);
  for (auto* r : t.libcode) {
    std::string sym = r->symbol.value_or("");
    out.print("ERROR " + r->orig + " (" + r->src + ") is linked library code from " + r->lib +
              (sym.empty() ? "" : ", `" + sym + "`") +
              ": remove the definition and reach it as the original does (through the library call or class that uses "
              "it); `// " +
              std::string(kind_name(r->kind)) + ":` is for decompiled code, `// LIBRARY: " + module + " " + r->orig +
              " <symbol>` for library code");
  }
  out.print("\nannotated " + std::to_string(results.size()) + ": " + std::to_string(t.matched.size()) + " match, " +
            std::to_string(differ) + " do not" + (cats.empty() ? "" : " (" + count_list(cats) + ")"));
  out.print("coverage: " + std::to_string(t.matched.size()) + "/" + std::to_string(universe) + " functions (" +
            percent(t.matched.size(), universe) + "), " + std::to_string(mbytes) + "/" + std::to_string(ubytes) +
            " bytes (" + percent(mbytes, ubytes) + ")");
  out.print("linked library code (not counted): " + std::to_string(orig.linked.size()) + " functions, " +
            std::to_string(lib_bytes) + " bytes" +
            (lib_counts.empty() ? "" : " (" + count_list(by_count(lib_counts)) + ")") + "; LIBRARY annotations " +
            std::to_string(lib_match) + "/" + std::to_string(lib_checked) + " match");
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

bool regression_gate(const std::string& path, const std::set<u64>& matched, const std::vector<Outcome>& results,
                     bool update, Out& out) {
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
  for (auto& [v, n] : prev)
    if (!matched.count(v)) lost.push_back(v);
  for (u64 v : lost) out.print("REGRESSION " + hex(v) + " " + prev[v]);
  for (u64 v : matched)
    if (!prev.count(v)) out.print("NEW MATCH  " + hex(v));
  if (update) {
    if (!lost.empty()) {
      out.print("refusing --update while regressions exist");
    } else {
      std::map<u64, std::string> names;
      for (auto& r : results) names[r.va] = r.name;
      std::set<u64> all(matched);
      for (auto& [v, n] : prev) all.insert(v);
      std::string text =
          "# Functions that byte-match. Maintained by verifier --update; --check fails if one regresses.\n";
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

// a file's SHA-256 (the original's configured hash, the name cache's key); throws when it cannot be read
std::string sha256_of(const std::string& f) {
  std::string h = sha256_file_if_present(f);
  if (h.empty()) throw std::runtime_error("cannot read " + f);
  return h;
}

// a destructor's annotation names the scalar deleting destructor when its address is a vtable slot (see
// pick_destructor)
void pick_destructors(std::vector<Annotation>& anns, const Original& orig, const Rebuilt& reb) {
  std::unordered_set<u64> slots;
  for (auto& [v, ss] : orig.vtables) slots.insert(ss.begin(), ss.end());
  auto has_code = [&](const std::string& n) { return !reb.lookup(n, std::nullopt, true).vas.empty(); };
  for (auto& ann : anns)
    if (ann.flags.dtor) ann.name = pick_destructor(ann.name, slots.count(ann.va) != 0, has_code);
}

// the comparison's exploring of every root (the compared annotations' functions, the GLOBALs' data) and its matching,
// before any result is judged
void explore_all(const std::vector<Annotation>& anns, const Original& orig, const Rebuilt& reb, Pairing& pairing,
                 Comparer& cmp, const std::vector<GlobalRoot>& globals) {
  for (auto& ann : anns) {
    if (!is_paired(ann.kind)) continue;
    if (auto f = compared_pair(ann, orig, reb, pairing)) cmp.explore({*f});
  }
  cmp.explore({}, data_pairs(globals));
  cmp.solve();
}

// every compared annotation's result, in address order: its stdout line and report entry made as it is evaluated,
// and what the summary reads kept
struct Evaluated {
  std::vector<Outcome> results;
  std::vector<Result> libcode;  // the LIBCODE results
  std::string lines;            // the results' stdout lines
  std::string report;           // "{ "results": [...]" when there is a report; the totals are added after
};
Evaluated evaluate_all(const std::vector<Annotation>& anns, const Original& orig, const Rebuilt& reb, Pairing& pairing,
                       Comparer& cmp, const Args& a, const Config& p, Out& out) {
  std::optional<u64> show;
  if (a.show) show = parse_hex(*a.show);
  std::vector<const Annotation*> order;
  for (auto& ann : anns)
    if (is_paired(ann.kind)) order.push_back(&ann);
  std::stable_sort(order.begin(), order.end(), [](auto* x, auto* y) { return x->va < y->va; });
  Evaluated ev;
  ev.results.reserve(order.size());
  if (a.json) {
    // room for the report at once (megabytes, else grown by doubling and copied each time): the last run's report is
    // about its size
    std::error_code ec;
    u64 last = std::filesystem::file_size(*a.json, ec);
    if (!ec) ev.report.reserve(last + last / 8);
    ev.report = "{\n  \"results\": ";
  }
  for (auto* ann : order) {
    Result r = evaluate(*ann, orig, reb, pairing, cmp, p.root, show && *show == ann->va, out, true);
    ev.lines += result_line(r, p.module);
    ev.lines += '\n';
    if (a.json) {
      ev.report += ev.results.empty() ? "[\n    " : ",\n    ";
      write_result(ev.report, r, 2);
    }
    ev.results.push_back({r.va, ann->kind, r.status, r.category, r.name});
    if (r.status == Status::LibCode) ev.libcode.push_back(std::move(r));
  }
  if (a.json) ev.report += ev.results.empty() ? "[]" : "\n  ]";
  return ev;
}

// stdout after the results' lines: GLOBALs whose bytes differ, and annotations that name nothing
void print_warnings(const std::vector<GlobalRoot>& globals, const std::vector<Ignored>& ignored, Comparer& cmp,
                    const std::string& root, Out& out) {
  for (auto& g : check_globals(globals, cmp))
    out.print("GLOBAL DIFFERS " + hex(g.ann->va) + " " + g.ann->name + " (" + where_of(g.ann->path, root) + ":" +
              std::to_string(g.ann->line) + "): " + g.problem + "; is the address right?");
  for (auto& ig : ignored)
    out.print(
        "IGNORED ANNOTATION " + where_of(ig.path, root) + ":" + std::to_string(ig.line) + ": `" + ig.text +
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
  Args a = parse_args(argc, argv);
  Config p = Config::load(a.config);
  Phases ph;
  Out out;

  Original orig(p, sha256_of);
  ph.mark("original");

  std::vector<Ignored> ignored;
  std::vector<Annotation> anns = parse_annotations(a.src, p.module, &ignored);
  check_duplicates(anns);
  ph.mark("annotations");

  // keyed by undname and by this verifier: the qualified names, signatures and owners kept with the undecorated
  // names are worked out by names.cpp, so another verifier build may give others
  std::string exe = self_exe();
  NameCache name_cache(
      p.names_cache(),
      "verifier names 2 " + sha256_of(p.undname) + " " + (exe.empty() ? std::string() : sha256_of(exe)), p.undname);
  Rebuilt reb(a.rebuilt, a.map, name_cache);
  ph.mark("rebuilt+names");

  pick_destructors(anns, orig, reb);
  Pairing pairing(orig, reb, anns);
  CodeCache orig_cache(&orig.img), rebuilt_cache(&reb.img);
  ph.mark("pairing");
  pairing.use_caches(orig_cache, rebuilt_cache);
  Comparer cmp(
      &orig.img, &reb.img, [&](u64 t) { return pairing.resolve(t); }, &orig.vtables,
      [&](u64 va) { return orig.ida_name(va); }, &pairing);
  pairing.prebind(cmp.m);
  ph.mark("prebind votes");
  auto globals = global_roots(
      anns, [&](const std::string& n) { return reb.lookup(n).vas; }, [&](u64 rva) { return pairing.orig_of(rva); },
      orig.img, reb.img);
  explore_all(anns, orig, reb, pairing, cmp, globals);
  ph.mark("explore+solve");

  Evaluated ev = evaluate_all(anns, orig, reb, pairing, cmp, a, p, out);
  ph.mark("evaluate");
  if (std::getenv("VERIFIER_TIMING")) {
    auto st = cmp.m.stats();
    std::fprintf(stderr, "matching: %zu nodes, %zu guesses (%zu hold), %zu roots compared again\n", st.nodes,
                 st.candidates, st.accepted, st.rejudged);
  }

  out.write(ev.lines);
  std::string().swap(ev.lines);
  print_warnings(globals, ignored, cmp, p.root, out);
  Totals totals = summarize(ev.results, ev.libcode, orig, out, p.module);
  ph.mark("globals+summary");

  // the names undname gave, for the next run (a check too: until the next --update, every run on this build would run
  // undname for them again)
  if (a.update || name_cache.has_new()) name_cache.save();
  if (a.json) {
    finish_report(ev.report, totals, *a.json);
    ph.mark("json");
  }
  int rc = totals.libcode.empty() ? 0 : 1;
  if (a.matched && regression_gate(*a.matched, totals.matched, ev.results, a.update, out)) rc = 1;
  rc = (a.check || a.update) ? rc : 0;
  return rc;
}

}  // namespace verifier
