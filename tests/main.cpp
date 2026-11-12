// The verifier's tests:
//   verifier-tests [fixtures.json] [-v]       exit code = number of failures
// The comparison cases of tests/data/fixtures.json (pairs of small synthetic PE images, the two functions to compare,
// the symbol mapping the comparer's hooks answer from, and the exact problems the comparison must report) run first,
// then the cases written in code, file by file. tools/fixture_dump prints a fixture case readably.
#include <cstdio>
#include <set>
#include <string>

#include "support.hpp"

#ifndef VERIFIER_FIXTURES
#define VERIFIER_FIXTURES "tests/data/fixtures.json"
#endif

namespace verifier::test {

namespace {
bool verbose = false;
int failures = 0;
std::string fixtures_path = VERIFIER_FIXTURES;
}  // namespace

const Value& fixtures() {
  static const Value doc = json::parse(read_file(fixtures_path));
  return doc;
}

void report(const std::string& name, const char* want, const Findings& probs, bool ok, std::string note) {
  std::replace(note.begin(), note.end(), '\n', ' ');
  std::set<std::string> cats;
  for (auto& p : probs) cats.insert(p.category);
  std::string got = probs.empty() ? "MATCH" : join(std::vector<std::string>(cats.begin(), cats.end()), ",");
  if (verbose && !probs.empty()) got += "  " + probs[0].detail.substr(0, 110);
  failures += !ok;
  std::string padded = name.size() >= 40 ? name : name + std::string(40 - name.size(), ' ');
  std::printf("%s %s want %-12s got %s%s\n", ok ? "ok " : "BAD", padded.c_str(), want ? want : "MATCH", got.c_str(),
              note.empty() ? "" : ("  (" + note + ")").c_str());
}

// a case passes when MATCH is wanted and there are no problems, or the wanted category is among them
bool verdict(const char* want, const Findings& probs) {
  if (!want) return probs.empty();
  for (auto& p : probs)
    if (p.category == want) return true;
  return false;
}

int main(int argc, char** argv) {
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "-v")
      verbose = true;
    else
      fixtures_path = a;
  }
  const Value& doc = fixtures();
  run_fixture_cases(doc);
  Cases cases;
  for (auto add : {add_names_cases, add_report_cases, add_compare_cases, add_pairing_cases, add_inputs_cases,
                   add_cache_cases, add_util_cases})
    add(cases);
  std::set<std::string> written;
  for (auto& c : cases) {
    written.insert(c.name);
    Findings probs;
    bool ok;
    std::string note;
    try {
      probs = c.fn();
      ok = verdict(c.want, probs);
      if (!ok && !probs.empty()) note = probs[0].detail.substr(0, 120);
    } catch (std::exception& e) {
      ok = false;
      note = std::string("ERROR ") + e.what();
    }
    report(c.name, c.want, probs, ok, note);
  }
  for (auto& o : doc["other"].arr)
    if (!written.count(o.as_str())) {
      ++failures;
      std::printf("BAD %s: listed under \"other\" but not written out\n", o.as_str().c_str());
    }
  std::printf("%zu cases, %d failures\n", doc["cases"].arr.size() + cases.size(), failures);
  return failures;
}

}  // namespace verifier::test

int main(int argc, char** argv) { return verifier::test::main(argc, argv); }
