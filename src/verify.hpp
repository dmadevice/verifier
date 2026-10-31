// The verifier's run: pair the annotated functions, compare each, print the results and summary, write the
// report and apply the regression gate.
#pragma once
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "json.hpp"
#include "pairing.hpp"
#include "diff_store.hpp"
#include "report.hpp"

namespace verifier {

// stdout, also kept for the replay
class Out {
 public:
  void print(const std::string& line);   // line + "\n"
  void write(const std::string& s);
  const std::string& text() const { return text_; }

 private:
  std::string text_;
};

// One annotation's result, as the report gives it (members in the report's order; the optional ones written when set)
struct Result {
  u64 va = 0;
  std::string orig, name, kind, src;
  std::vector<std::string> overloads;   // written when more than one
  std::string status;
  bool linked = false;                  // LIBCODE: the library and the symbol (if any)
  std::string lib;
  std::optional<std::string> symbol;
  bool compared = false;                // MATCH / DIFF: the members below
  i64 osize = 0, rsize = 0;
  std::optional<std::string> category;
  std::vector<std::string> unresolved, problems;
  struct FirstDiff { i64 index; std::string orig, rebuilt; };
  std::optional<FirstDiff> first_diff;
  bool has_diff = false;
  std::vector<std::string> diff;
};
void write_result(std::string& out, const Result& r, int level);   // as JSON, an object at `level`

Result evaluate(const Annotation& ann, const Original& orig, const Rebuilt& reb, Pairing& pairing, Comparer& cmp,
                const std::string& root, bool show, Out& out, bool want_diff = true, DiffStore* diffs = nullptr);
std::string result_line(const Result& r, const std::string& module);

// GLOBAL annotations on read-only data whose bytes are not the original's (warnings)
struct GlobalDiff { const Annotation* ann; std::string problem; };
std::vector<GlobalDiff> check_globals(const std::vector<Annotation>& anns, const std::function<std::vector<u64>(const std::string&)>& lookup,
                                      const std::unordered_map<u64, u64>& reb_to_orig, Comparer& cmp);

struct Args {
  std::string config = "verifier.conf";
  std::string rebuilt, map;
  std::optional<std::string> matched, json, show;
  std::vector<std::string> src;
  bool check = false, update = false;
};
// The replay record's command: the arguments, the root and the configuration's contents (a caller may write the
// configuration before every run). A record replays only its own command, so the keys below hold only the inputs.
std::string command_key(const std::vector<std::string>& args, const Config& p);
// the replay key: the verifier (the executable's hash) and every input file it reads, each by its SHA-256 (`hash`
// gives a file's, "" when it is absent; `sources` lists the files under --src in list_files order). With a cache the
// original and the exports are read only through the snapshot: its key stands for them.
std::string run_key(const Args& a, const Config& p, const std::string& verifier, const std::vector<std::string>& sources,
                    const std::function<std::string(const std::string&)>& hash);
// the same, listing --src and hashing every file
std::string run_key(const Args& a, const Config& p, const std::string& verifier);
// The replay's first check, from metadata alone: the verifier's and every input file's path, size and modification
// time. "" when an input changed within the last two seconds: a change in the same tick of the file clock could leave
// its time and size as they were, so such inputs are checked by contents (run_key) instead.
std::string stamp_key(const Args& a, const Config& p, const std::string& exe);
// the same from the sources' listing (list_files of each --src, in order), "" when an input is not older than `recent`
// (the file clock's ticks)
std::string stamp_key(const Args& a, const Config& p, const std::string& exe, const std::vector<ListedFile>& sources,
                      i64 recent);
i64 two_seconds_ago();   // in the file clock's ticks

// the command line: exits the process when it has run (without freeing what it built); returns early only for a replay
int run(int argc, char** argv);

}  // namespace verifier
