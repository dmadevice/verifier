#include "annotations.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <map>
#include <regex>

#include "names.hpp"

namespace verifier {

bool is_counted(const std::string& k) { return k == "FUNCTION" || k == "SYNTHETIC" || k == "TEMPLATE"; }
bool is_paired(const std::string& k) { return is_counted(k) || k == "LIBRARY"; }

std::optional<std::string> sig_flag(const std::set<std::string>& flags) {
  // a flags set holds at most one SIG= entry
  for (auto& f : flags) if (starts_with(f, "SIG=")) return f.substr(4);
  return std::nullopt;
}

std::vector<std::string> walk_files(const std::string& root) {
  namespace fs = std::filesystem;
  std::vector<std::string> out;
  std::error_code ec;
  if (!fs::is_directory(root, ec)) return out;
  std::vector<std::string> files, dirs;
  for (auto it = fs::directory_iterator(root, ec); !ec && it != fs::directory_iterator(); it.increment(ec)) {
    std::error_code e2;
    bool d = it->is_directory(e2) && !it->is_symlink(e2);
    std::string name = it->path().filename().string();
    (d ? dirs : files).push_back(name);
  }
  std::sort(files.begin(), files.end());
  for (auto& f : files) out.push_back(path_join(root, f));
  for (auto& d : dirs) {
    auto sub = walk_files(path_join(root, d));
    out.insert(out.end(), sub.begin(), sub.end());
  }
  return out;
}

namespace {

const char* const KINDS[] = {"FUNCTION", "STUB", "SYNTHETIC", "TEMPLATE", "LIBRARY", "GLOBAL", "VTABLE"};

// `//\s*(FUNCTION|...):\s*<module>\s+0x([0-9a-fA-F]+)\s*(.*)$` anywhere in the line: kind, hex, rest
bool match_annotation(const std::string& line, const std::string& module, std::string& kind, std::string& hexs,
                      std::string& rest) {
  for (size_t p = line.find("//"); p != std::string::npos; p = line.find("//", p + 1)) {
    size_t i = p + 2;
    while (i < line.size() && is_space(line[i])) ++i;
    const char* k = nullptr;
    for (const char* c : KINDS) {
      size_t n = std::strlen(c);
      if (line.compare(i, n, c) == 0 && line.compare(i + n, 1, ":") == 0) { k = c; break; }
    }
    if (!k) continue;
    i += std::strlen(k) + 1;
    while (i < line.size() && is_space(line[i])) ++i;
    if (line.compare(i, module.size(), module) != 0) continue;
    i += module.size();
    size_t j = i;
    while (j < line.size() && is_space(line[j])) ++j;
    if (j == i || line.compare(j, 2, "0x") != 0) continue;
    j += 2;
    size_t h = j;
    while (h < line.size() && std::isxdigit(static_cast<unsigned char>(line[h]))) ++h;
    if (h == j) continue;
    size_t r = h;
    while (r < line.size() && is_space(line[r])) ++r;
    kind = k;
    hexs = line.substr(j, h - j);
    rest = line.substr(r);
    return true;
  }
  return false;
}

}  // namespace

std::vector<Annotation> parse_annotations(const std::vector<std::string>& roots, const std::string& module,
                                          std::vector<Ignored>* ignored) {
  static const std::regex global_decl(R"(([A-Za-z_]\w*)\s*(?:\[[^\]]*\])*\s*(?:=|;|\{))");
  static const std::regex class_decl(R"(\b(?:class|struct)\s+(?:__declspec\(\w+\)\s+)?([A-Za-z_][\w:]*))");
  std::vector<Annotation> out;
  for (auto& root : roots) {
    for (auto& path : walk_files(root)) {
      if (!(ends_with(path, ".cpp") || ends_with(path, ".h") || ends_with(path, ".c") || ends_with(path, ".hpp") ||
            ends_with(path, ".inl")))
        continue;
      auto lines = read_lines(path);
      for (size_t i = 0; i < lines.size(); ++i) {
        std::string kind, hexs, rest0;
        if (!match_annotation(lines[i], module, kind, hexs, rest0)) continue;
        u64 va = parse_hex(hexs);
        std::string rest = strip(rest0);
        std::set<std::string> flags;
        if (starts_with(rest, "FOLDED")) { flags.insert("FOLDED"); rest = strip(rest.substr(6)); }
        std::vector<std::string> following(lines.begin() + long(i) + 1, lines.begin() + long(std::min(lines.size(), i + 4)));
        size_t before = out.size();
        if (kind == "SYNTHETIC" || kind == "TEMPLATE" || kind == "LIBRARY") {
          std::string name = rest;
          if (name.empty() && !following.empty()) {
            std::string f = strip(following[0]);
            size_t k = 0;
            while (k < f.size() && f[k] == '/') ++k;
            name = strip(f.substr(k));
          }
          long p = param_start(name);
          if (p > 0 && ends_with(name, ")")) {   // `Name(params)`: pairs with that overload only
            flags.insert("SIG=" + norm_params(name.substr(size_t(p))));
            name = strip(name.substr(0, size_t(p)));
          }
          out.push_back({kind, va, name, flags, path, int(i + 1)});
          continue;
        }
        if (starts_with(rest, "(") && ends_with(rest, ")")) flags.insert("SIG=" + norm_params(rest));
        if (kind == "GLOBAL") {
          for (auto& nxt : following) {
            std::smatch m;
            if (std::regex_search(nxt, m, global_decl)) { out.push_back({kind, va, m[1].str(), flags, path, int(i + 1)}); break; }
          }
        } else if (kind == "VTABLE") {
          for (auto& nxt : following) {
            std::smatch m;
            if (std::regex_search(nxt, m, class_decl)) { out.push_back({kind, va, m[1].str(), flags, path, int(i + 1)}); break; }
          }
        } else {
          for (auto& nxt : following) {
            auto name = definition_name(nxt);
            if (name) {
              if (name->find('~') != std::string::npos) flags.insert("DTOR");
              out.push_back({kind, va, *name, flags, path, int(i + 1)});
              break;
            }
          }
        }
        if (out.size() == before && ignored) ignored->push_back({path, int(i + 1), strip(lines[i])});
      }
    }
  }
  return out;
}

void check_duplicates(const std::vector<Annotation>& anns) {
  std::map<u64, std::pair<std::string, bool>> seen;
  for (auto& a : anns) {
    if (!is_paired(a.kind)) continue;
    bool folded = a.flags.count("FOLDED") != 0;
    auto it = seen.find(a.va);
    if (it != seen.end() && !(folded && it->second.second)) {
      std::fprintf(stderr, "duplicate annotation %s: %s and %s:%d (mark /OPT:ICF folds FOLDED)\n", hex(a.va).c_str(),
                   it->second.first.c_str(), a.path.c_str(), a.line);
      std::exit(1);
    }
    seen[a.va] = {a.path + ":" + std::to_string(a.line), folded};
  }
}

}  // namespace verifier
