// One compared annotation: its result (status, sizes, category, problems, the instruction diff), worked out from the
// pairing and the comparison, and its stdout line and report entry.
#pragma once
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "diff_store.hpp"
#include "pairing.hpp"
#include "policy.hpp"
#include "report.hpp"

namespace verifier {

// stdout
class Out {
 public:
  void print(const std::string& line);  // line + "\n"
  void write(const std::string& s);
};

// What a compared annotation came to
enum class Status : u8 {
  Match,      // the rebuilt function is the original's
  Diff,       // compared, and something differs (the result's category and problems say what)
  Missing,    // no rebuilt symbol for the annotation's name
  Ambiguous,  // the name matches several rebuilt symbols
  BadAddr,    // no original function at the annotation's address
  LibCode,    // a counted annotation on code a linked library supplies
};
std::string_view status_name(Status s);  // as reported: MATCH, DIFF, ...

// One annotation's result, as the report gives it (members in the report's order; the optional ones written when set)
struct Result {
  u64 va = 0;
  std::string orig, name;
  Kind kind = Kind::Function;
  std::string src;
  std::vector<std::string> overloads;  // written when more than one
  Status status = Status::Match;
  bool linked = false;  // LIBCODE: the library and the symbol (if any)
  std::string lib;
  std::optional<std::string> symbol;
  bool compared = false;  // MATCH / DIFF: the members below
  i64 osize = 0, rsize = 0;
  std::optional<Category> category;
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

// the functions evaluate() compares for an annotation (nullopt: it reports without comparing), each a root the
// comparison explores before any is judged
std::optional<FnPair> compared_pair(const Annotation& ann, const Original& orig, const Rebuilt& reb,
                                    const Pairing& pairing);
// an annotation's result: its functions judged (after the comparer has explored every root and solved)
Result evaluate(const Annotation& ann, const Original& orig, const Rebuilt& reb, Pairing& pairing, Comparer& cmp,
                const std::string& root, bool show, Out& out, bool want_diff = true, DiffStore* diffs = nullptr);
std::string result_line(const Result& r, const std::string& module);

// a source path as the report gives it: relative to the project root
const std::string& where_of(std::string_view path, const std::string& root);
// each annotation's path as the report gives it (Annotation::where), worked out once for each file
void set_where(std::vector<Annotation>& anns, const std::string& root);

}  // namespace verifier
