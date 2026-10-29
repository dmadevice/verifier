// The project configuration: where the inputs are and the annotation tag. A text file of `key = value` lines
// (`#` starts a comment); relative paths are relative to the file's directory, which is also the project root
// that source paths in the report are given relative to.
#pragma once
#include <string>

namespace verifier {

struct Config {
  std::string file, root;            // the configuration file and its directory
  std::string module;                // annotation tag: `// FUNCTION: <module> 0x<va>`
  std::string original;              // the original binary
  std::string original_sha256;       // its expected SHA-256 (optional)
  std::string functions, vtables;    // IDA exports: functions (required), vtables (optional)
  std::string data_items, data_names;   // IDA database exports (optional): alignment items, named data
  std::string library_matches;       // library functions found in the original (optional)
  std::string library_functions;     // other functions attributed to libraries (optional)
  std::string symbols;               // extra `name 0x<va>` lines (optional)
  std::string undname;               // MSVC undname.exe, or a program printing its output
  std::string cache_dir;             // where the undecorated-name cache is kept (optional)

  std::string names_cache() const;   // the cache file ("" when there is no cache_dir)
  // the file at `path`; exits with a message (code 2) when it is unreadable or a required key is missing
  static Config load(const std::string& path);
};

}  // namespace verifier
