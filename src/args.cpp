#include "args.hpp"

#include <cstdio>
#include <cstdlib>

#include "util.hpp"

namespace verifier {

namespace {

[[noreturn]] void usage(const std::string& err) {
  std::fprintf(stderr,
               "usage: verifier [--config FILE] --rebuilt REBUILT --map MAP --src SRC [SRC ...] [--matched MATCHED]\n"
               "                  [--check] [--update] [--json JSON] [--show SHOW]\n"
               "verifier: error: %s\n", err.c_str());
  std::exit(2);
}

}  // namespace

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

}  // namespace verifier
