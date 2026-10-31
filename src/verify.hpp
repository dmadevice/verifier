// The verifier's run: pair the annotated functions, compare each, print the results and summary, write the
// report and apply the regression gate.
#pragma once
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "args.hpp"
#include "diff_store.hpp"
#include "json.hpp"
#include "pairing.hpp"
#include "report.hpp"

namespace verifier {

// stdout, also kept for the replay
class Out {
 public:
  void print(const std::string& line);  // line + "\n"
  void write(const std::string& s);
  const std::string& text() const { return text_; }

 private:
  std::string text_;
};

// One annotation's result, as the report gives it (members in the report's order; the optional ones written when set)
struct Result {
  u64 va = 0;
  std::string orig, name, kind, src;
  std::vector<std::string> overloads;  // written when more than one
  std::string status;
  bool linked = false;  // LIBCODE: the library and the symbol (if any)
  std::string lib;
  std::optional<std::string> symbol;
  bool compared = false;  // MATCH / DIFF: the members below
  i64 osize = 0, rsize = 0;
  std::optional<std::string> category;
  std::vector<std::string> unresolved, problems;
  struct FirstDiff {
    i64 index;
    std::string orig, rebuilt;
  };
  std::optional<FirstDiff> first_diff;
  bool has_diff = false;
  std::vector<std::string> diff;
};
void write_result(std::string& out, const Result& r, int level);  // as JSON, an object at `level`

Result evaluate(const Annotation& ann, const Original& orig, const Rebuilt& reb, Pairing& pairing, Comparer& cmp,
                const std::string& root, bool show, Out& out, bool want_diff = true, DiffStore* diffs = nullptr);
std::string result_line(const Result& r, const std::string& module);

// GLOBAL annotations on read-only data whose bytes are not the original's (warnings)
struct GlobalDiff {
  const Annotation* ann;
  std::string problem;
};
std::vector<GlobalDiff> check_globals(const std::vector<Annotation>& anns,
                                      const std::function<std::vector<u64>(const std::string&)>& lookup,
                                      const std::function<std::optional<u64>(u64)>& orig_of, Comparer& cmp);

// the command line: exits the process when it has run (without freeing what it built); returns early only for a replay
int run(int argc, char** argv);

}  // namespace verifier
