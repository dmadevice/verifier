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

// A run's arguments, configuration and phase timer, and its replay record's bookkeeping: the files it hashes (each
// once), and the record's command, stamps and key, worked out only when the record needs them
class RunState {
 public:
  RunState(int argc, char** argv)
      : a(parse_args(argc, argv)),
        p(Config::load(a.config)),
        args_(argv + 1, argv + argc),
        exe_(self_exe()),
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
    if (!load_last(
            last_, command_, image_stamp_, [&] { return stamps_now(); }, [&] { return hash_if_present(a.rebuilt); },
            walk_key, rec) ||
        !(a.json ? !rec.report_hash.empty() && content_hash_file_if_present(*a.json) == rec.report_hash
                 : rec.report_hash.empty()))
      return std::nullopt;
    std::fputs("verifier inputs unchanged since the last check: its results follow\n", stdout);
    std::fwrite(rec.out.data(), 1, rec.out.size(), stdout);
    std::fflush(stdout);
    // the same contents under new stamps (a file rewritten as it was): the record takes them, for the next run
    if (!rec.by_stamps && !stamps_now().empty())
      save_last(last_, command_, image_stamp_, stamps_, hash_if_present(a.rebuilt), key_, rec.out, rec.report_hash,
                rec.rc);
    return rec.rc;
  }

  // an input's bytes as the run reads them: its hash for the record's key, worked out while they are at hand
  std::function<void(const std::string&, std::string_view)> read() {
    if (last_.empty() || !key_.empty()) return nullptr;
    return [this](const std::string& f, std::string_view data) { hashes_.try_emplace(f, content_hash(data)); };
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
                       Comparer& cmp, DiffStore& diffs, const RunState& s, Out& out) {
  std::optional<u64> show;
  if (s.a.show) show = parse_hex(*s.a.show);
  std::vector<const Annotation*> order;
  for (auto& ann : anns)
    if (is_paired(ann.kind)) order.push_back(&ann);
  std::stable_sort(order.begin(), order.end(), [](auto* x, auto* y) { return x->va < y->va; });
  Evaluated ev;
  ev.results.reserve(order.size());
  if (s.a.json) {
    // room for the report at once (megabytes, else grown by doubling and copied each time): the last run's report is
    // about its size
    std::error_code ec;
    u64 last = std::filesystem::file_size(*s.a.json, ec);
    if (!ec) ev.report.reserve(last + last / 8);
    ev.report = "{\n  \"results\": ";
  }
  for (auto* ann : order) {
    Result r = evaluate(*ann, orig, reb, pairing, cmp, s.p.root, show && *show == ann->va, out, true, &diffs);
    ev.lines += result_line(r, s.p.module);
    ev.lines += '\n';
    if (s.a.json) {
      ev.report += ev.results.empty() ? "[\n    " : ",\n    ";
      write_result(ev.report, r, 2);
    }
    ev.results.push_back({r.va, ann->kind, r.status, r.category, r.name});
    if (r.status == Status::LibCode) ev.libcode.push_back(std::move(r));
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
  RunState s(argc, argv);
  if (auto rc = s.replay()) return *rc;
  if (s.keeps_record()) s.ph.mark("replay key");
  const Args& a = s.a;
  const Config& p = s.p;
  Out out;

  Original orig(p, sha256_of);
  s.ph.mark("original");

  // each source file's annotations kept between runs (with a cache directory): unchanged files are not read again
  // (the cache is freed once the annotations are read)
  std::vector<Ignored> ignored;
  std::vector<Annotation> anns;
  {
    SourceCache sources(s.build_cache("sources-cache.bin"), "verifier " + s.self_hash() + " module " + p.module,
                        s.start());
    anns = parse_annotations(a.src, p.module, &ignored, nullptr, &sources, s.hashed());
    sources.save();
    if (std::getenv("VERIFIER_TIMING"))
      std::fprintf(stderr, "source files from the sources cache: %zu (read %zu)\n", sources.stats().hits,
                   sources.stats().misses);
  }
  check_duplicates(anns);
  s.ph.mark("annotations");

  // keyed by undname and by this verifier: the qualified names, signatures and owners kept with the undecorated
  // names are worked out by names.cpp, so another verifier build may give others
  NameCache name_cache(p.names_cache(), "verifier names 2 " + sha256_of(p.undname) + " " + s.self_hash(), p.undname);
  Rebuilt reb(a.rebuilt, a.map, name_cache, s.read());
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
  auto globals = global_roots(
      anns, [&](const std::string& n) { return reb.lookup(n).vas; }, [&](u64 rva) { return pairing.orig_of(rva); },
      orig.img, reb.img);
  explore_all(anns, orig, reb, pairing, cmp, globals);
  s.ph.mark("explore+solve");

  Evaluated ev = evaluate_all(anns, orig, reb, pairing, cmp, diff_store, s, out);
  s.ph.mark("evaluate");
  if (std::getenv("VERIFIER_TIMING")) {
    auto st = cmp.m.stats();
    std::fprintf(stderr, "matching: %zu nodes, %zu guesses (%zu hold), %zu roots compared again\n", st.nodes,
                 st.candidates, st.accepted, st.rejudged);
  }
  print_cache_stats(orig_cache, rebuilt_cache, orig_store, diff_store);
  orig_store.save();
  diff_store.save();
  s.ph.mark("code and diff stores");

  out.write(ev.lines);
  std::string().swap(ev.lines);
  print_warnings(globals, ignored, cmp, p.root, out);
  Totals totals = summarize(ev.results, ev.libcode, orig, out, p.module);
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
  s.ph.mark("replay record");
  // everything is written: leave without freeing the run's structures, which takes a tenth of a second for nothing
  std::fflush(nullptr);
  std::_Exit(rc);
}

}  // namespace verifier
