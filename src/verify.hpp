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
#include "result.hpp"

namespace verifier {

// GLOBAL annotations on read-only data, each with a rebuilt symbol it pairs with: their bytes are compared (roots the
// comparison explores with the functions), and those that are not the original's are warnings
struct GlobalRoot {
  const Annotation* ann;
  u64 rva;
};
std::vector<GlobalRoot> global_roots(const std::vector<Annotation>& anns,
                                     const std::function<std::vector<u64>(const std::string&)>& lookup,
                                     const std::function<std::optional<u64>(u64)>& orig_of, const Image& O,
                                     const Image& R);
std::vector<std::pair<u64, u64>> data_pairs(const std::vector<GlobalRoot>& roots);  // (original, rebuilt)
struct GlobalDiff {
  const Annotation* ann;
  std::string problem;
};
std::vector<GlobalDiff> check_globals(const std::vector<GlobalRoot>& roots, Comparer& cmp);  // judged (after solve)

// the command line: exits the process when it has run (without freeing what it built); returns early only for a replay
int run(int argc, char** argv);

}  // namespace verifier
