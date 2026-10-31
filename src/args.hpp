// The command line's arguments.
#pragma once
#include <optional>
#include <string>
#include <vector>

namespace verifier {

struct Args {
  std::string config = "verifier.conf";
  std::string rebuilt, map;
  std::optional<std::string> matched, json, show;
  std::vector<std::string> src;
  bool check = false, update = false;
};
// the arguments, as given; exits (code 2, the usage on stderr) when they are not
Args parse_args(int argc, char** argv);

}  // namespace verifier
