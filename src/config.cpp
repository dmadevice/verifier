#include "config.hpp"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <map>

#include "util.hpp"

namespace verifier {

namespace {

[[noreturn]] void fail(const std::string& why) {
  std::fprintf(stderr, "verifier: %s\n", why.c_str());
  std::exit(2);
}

}  // namespace

std::string Config::names_cache() const { return cache_dir.empty() ? "" : path_join(cache_dir, "undname-cache.txt"); }

Config Config::load(const std::string& path) {
  if (!file_exists(path)) fail("no configuration file " + path + " (see --config)");
  Config c;
  c.file = abspath(path);
  c.root = dirname(c.file);
  std::map<std::string, std::string> kv;
  int n = 0;
  for (auto& raw : read_lines(path)) {
    ++n;
    std::string line = raw;
    if (size_t h = line.find('#'); h != std::string::npos) line.resize(h);
    line = strip(line);
    if (line.empty()) continue;
    size_t eq = line.find('=');
    if (eq == std::string::npos) fail(path + ":" + std::to_string(n) + ": expected `key = value`");
    kv[strip(line.substr(0, eq))] = strip(line.substr(eq + 1));
  }
  auto take = [&](const char* key, bool is_path, bool required) {
    auto it = kv.find(key);
    if (it == kv.end() || it->second.empty()) {
      if (required) fail(path + ": `" + key + "` is required");
      return std::string();
    }
    std::string v = it->second;
    kv.erase(it);
    if (!is_path) return v;
    std::filesystem::path p(v);
    return normpath(p.is_absolute() ? v : path_join(c.root, v));
  };
  c.module = take("module", false, true);
  c.original = take("original", true, true);
  c.original_sha256 = lower(take("original_sha256", false, false));
  c.functions = take("functions", true, true);
  c.vtables = take("vtables", true, false);
  c.data_items = take("data_items", true, false);
  c.data_names = take("data_names", true, false);
  c.library_matches = take("library_matches", true, false);
  c.library_functions = take("library_functions", true, false);
  c.symbols = take("symbols", true, false);
  c.undname = take("undname", true, true);
  c.cache_dir = take("cache_dir", true, false);
  if (!kv.empty()) fail(path + ": unknown key `" + kv.begin()->first + "`");
  for (const std::string* f : {&c.original, &c.functions, &c.vtables, &c.data_items, &c.data_names, &c.library_matches,
                               &c.library_functions, &c.symbols, &c.undname})
    if (!f->empty() && !file_exists(*f)) fail(path + ": no file " + *f);
  for (char ch : c.module)
    if (!is_word(ch)) fail(path + ": `module` must be a single word (letters, digits, _)");
  return c;
}

}  // namespace verifier
