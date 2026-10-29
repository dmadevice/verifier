// The verifier's run: pair the annotated functions, compare each, print the results and summary, write the
// report and apply the regression gate.
#pragma once
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

#include "json.hpp"
#include "pairing.hpp"
#include "report.hpp"

namespace verifier {

// stdout, also kept for the --check replay
class Out {
 public:
  void print(const std::string& line);   // line + "\n"
  void write(const std::string& s);
  const std::string& text() const { return text_; }

 private:
  std::string text_;
};

json::Value evaluate(const Annotation& ann, const Original& orig, const Rebuilt& reb, Pairing& pairing, Comparer& cmp,
                     const std::string& root, bool show, Out& out, bool want_diff = true);
std::string result_line(const json::Value& r, const std::string& module);

// GLOBAL annotations on read-only data whose bytes are not the original's (warnings)
struct GlobalDiff { const Annotation* ann; std::string problem; };
std::vector<GlobalDiff> check_globals(const std::vector<Annotation>& anns, const std::function<std::vector<u64>(const std::string&)>& lookup,
                                      const std::unordered_map<u64, u64>& reb_to_orig, Comparer& cmp);

struct Args {
  std::string config = "verifier.conf";
  std::string rebuilt, map, matched, json, show;
  std::vector<std::string> src;
  bool check = false, update = false, has_matched = false, has_json = false, has_show = false;
};
// the --check replay key: the verifier (the executable's hash), its arguments and every file it reads
std::string run_key(const std::vector<std::string>& args, const Args& a, const Config& p, const std::string& verifier);

int run(int argc, char** argv);

}  // namespace verifier
