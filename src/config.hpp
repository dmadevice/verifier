// The project configuration: where the inputs are and the annotation tag. A text file of `key = value` lines
// (`#` starts a comment); relative paths are relative to the file's directory, which is also the project root
// that source paths in the report are given relative to.
#pragma once
#include <array>
#include <string>

namespace verifier {

struct Config {
  std::string file, root;              // the configuration file and its directory
  std::string module;                  // annotation tag: `// FUNCTION: <module> 0x<va>`
  std::string original;                // the original binary
  std::string original_sha256;         // its expected SHA-256 (optional)
  std::string functions, vtables;      // IDA exports: functions (required), vtables (optional)
  std::string data_items, data_names;  // IDA database exports (optional): alignment items, named data
  std::string library_matches;         // library functions found in the original (optional)
  std::string library_functions;       // other functions attributed to libraries (optional)
  std::string symbols;                 // extra `name 0x<va>` lines (optional)
  std::string undname;                 // MSVC undname.exe, or a program printing its output
  std::string cache_dir;               // where the name cache and the exports snapshot are kept (optional)

  std::string cache_file(const std::string& name) const;  // a file in cache_dir ("" when there is none)
  std::string names_cache() const { return cache_file("undname-cache.bin"); }
  // the original and the exports: what the snapshot is made from
  std::array<const std::string*, 8> snapshot_inputs() const {
    return {&original, &functions, &vtables, &data_items, &data_names, &library_matches, &library_functions, &symbols};
  }
  // the file at `path`; exits with a message (code 2) when it is unreadable or a required key is missing
  static Config load(const std::string& path);
};

}  // namespace verifier
