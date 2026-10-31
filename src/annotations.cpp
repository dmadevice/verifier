#include "annotations.hpp"

#include <cstring>

#include "content_hash.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <limits>
#include <map>

#include "names.hpp"

#ifdef _WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace verifier {

bool is_counted(const std::string& k) { return k == "FUNCTION" || k == "SYNTHETIC" || k == "TEMPLATE"; }
bool is_paired(const std::string& k) { return is_counted(k) || k == "LIBRARY"; }

std::optional<std::string> sig_flag(const AnnotationFlags& flags) {
  if (flags.sig.empty()) return std::nullopt;
  return flags.sig;
}

namespace {

// list_files, appending to out (a link to a directory is a file): on Windows the sizes and times come from the listing
// itself (FindFirstFileEx gives every entry's), elsewhere from a stat each
void walk(const std::string& root, std::vector<ListedFile>& out) {
  std::vector<ListedFile> files;   // by name, until joined to root
  std::vector<std::string> dirs;
#ifdef _WIN32
  WIN32_FIND_DATAW d;
  HANDLE h = FindFirstFileExW((std::filesystem::path(root) / L"*").c_str(), FindExInfoBasic, &d, FindExSearchNameMatch,
                              nullptr, FIND_FIRST_EX_LARGE_FETCH);
  if (h == INVALID_HANDLE_VALUE) return;   // no such directory
  do {
    if (!wcscmp(d.cFileName, L".") || !wcscmp(d.cFileName, L"..")) continue;
    std::string name = std::filesystem::path(d.cFileName).string();
    bool link = (d.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) && d.dwReserved0 == IO_REPARSE_TAG_SYMLINK;
    if ((d.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && !link) {
      dirs.push_back(std::move(name));
      continue;
    }
    // the file clock's ticks are FILETIME's (100 ns since 1601)
    files.push_back({std::move(name), (u64(d.nFileSizeHigh) << 32) | d.nFileSizeLow,
                     i64((u64(d.ftLastWriteTime.dwHighDateTime) << 32) | d.ftLastWriteTime.dwLowDateTime)});
  } while (FindNextFileW(h, &d));
  FindClose(h);
#else
  namespace fs = std::filesystem;
  std::error_code ec;
  if (!fs::is_directory(root, ec)) return;
  for (auto it = fs::directory_iterator(root, ec); !ec && it != fs::directory_iterator(); it.increment(ec)) {
    std::error_code e2;
    std::string name = it->path().filename().string();
    if (it->is_directory(e2) && !it->is_symlink(e2)) {
      dirs.push_back(std::move(name));
      continue;
    }
    ListedFile f{std::move(name)};
    f.size = it->file_size(e2);
    if (e2) f.size = u64(-1);
    auto time = it->last_write_time(e2);
    f.time = e2 ? std::numeric_limits<i64>::max() : i64(time.time_since_epoch().count());   // unknown: recent
    files.push_back(std::move(f));
  }
#endif
  std::sort(files.begin(), files.end(), [](auto& x, auto& y) { return x.path < y.path; });
  std::sort(dirs.begin(), dirs.end());
  for (auto& f : files) {
    f.path = path_join(root, f.path);
    out.push_back(std::move(f));
  }
  for (auto& sub : dirs) walk(path_join(root, sub), out);
}

}  // namespace

std::vector<ListedFile> list_files(const std::string& root) {
  std::vector<ListedFile> out;
  walk(root, out);
  return out;
}

namespace {

const char* const KINDS[] = {"FUNCTION", "STUB", "SYNTHETIC", "TEMPLATE", "LIBRARY", "GLOBAL", "VTABLE"};

// `//\s*(FUNCTION|...):\s*<module>\s+0x([0-9a-fA-F]+)\s*(.*)$` anywhere in the line: kind, hex, rest
bool match_annotation(std::string_view line, const std::string& module, std::string& kind, std::string& hexs,
                      std::string& rest) {
  for (size_t p = line.find("//"); p != std::string_view::npos; p = line.find("//", p + 1)) {
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
    hexs = std::string(line.substr(j, h - j));
    rest = std::string(line.substr(r));
    return true;
  }
  return false;
}

}  // namespace

namespace {

// one file's annotations (appended to out) and the annotations naming nothing (to ignored)
void parse_file(std::string_view data, const std::string& path, std::string_view kept_path, const std::string& module,
                std::vector<Annotation>& out, std::vector<Ignored>* ignored) {
  std::vector<std::string_view> lines;
  for_each_line(data, [&](std::string_view l) { lines.push_back(l); });
  for (size_t i = 0; i < lines.size(); ++i) {
    std::string kind, hexs, rest0;
    if (!match_annotation(lines[i], module, kind, hexs, rest0)) continue;
    u64 va = parse_hex(hexs);
    std::string rest = strip(rest0);
    AnnotationFlags flags;
    if (starts_with(rest, "FOLDED")) { flags.folded = true; rest = strip(rest.substr(6)); }
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
        flags.sig = norm_params(name.substr(size_t(p)));
        name = strip(name.substr(0, size_t(p)));
      }
      out.push_back({kind, va, name, flags, kept_path, int(i + 1)});
      continue;
    }
    if (starts_with(rest, "(") && ends_with(rest, ")")) flags.sig = norm_params(rest);
    if (kind == "GLOBAL") {
      for (auto& nxt : following) {
        if (auto name = global_decl_name(nxt)) { out.push_back({kind, va, *name, flags, kept_path, int(i + 1)}); break; }
      }
    } else if (kind == "VTABLE") {
      for (auto& nxt : following) {
        if (auto name = class_decl_name(nxt)) { out.push_back({kind, va, *name, flags, kept_path, int(i + 1)}); break; }
      }
    } else {
      for (auto& nxt : following) {
        auto name = definition_name(nxt);
        if (name) {
          if (name->find('~') != std::string::npos) flags.dtor = true;
          out.push_back({kind, va, *name, flags, kept_path, int(i + 1)});
          break;
        }
      }
    }
    if (out.size() == before && ignored) ignored->push_back({path, int(i + 1), strip(lines[i])});
  }
}

}  // namespace

std::vector<Annotation> parse_annotations(const std::vector<std::string>& roots, const std::string& module,
                                          std::vector<Ignored>* ignored,
                                          const std::function<void(const ListedFile&, std::string_view)>& seen,
                                          SourceCache* cache,
                                          const std::function<void(const ListedFile&, const std::string&)>& hashed) {
  std::vector<Annotation> out;
  for (auto& root : roots) {
    for (auto& file : list_files(root)) {
      const std::string& path = file.path;
      bool source = ends_with(path, ".cpp") || ends_with(path, ".h") || ends_with(path, ".c") || ends_with(path, ".hpp") ||
                    ends_with(path, ".inl");
      if (!source && !seen && !hashed) continue;
      if (const SourceCache::Entry* e = cache ? cache->find(file) : nullptr) {   // as the cache has it: not read
        if (hashed) hashed(file, e->hash);
        std::string_view kept_path = keep_text(path);
        for (auto& a : e->anns) out.push_back({a.kind, a.va, a.name, a.flags, kept_path, a.line});
        if (ignored) for (auto& ig : e->ignored) ignored->push_back({path, ig.line, ig.text});
        cache->keep(file, *e);
        continue;
      }
      std::string data = read_file(path);
      if (seen) seen(file, data);
      std::string hash = hashed || cache ? content_hash(data) : std::string();
      if (hashed) hashed(file, hash);
      SourceCache::Entry e{hash, {}, {}};
      if (source && data.find(module) != std::string::npos) {   // else no annotation of this module here
        std::vector<Annotation> anns;
        std::vector<Ignored> ign;
        parse_file(data, path, keep_text(path), module, anns, &ign);
        for (auto& a : anns) out.push_back(a);
        if (ignored) ignored->insert(ignored->end(), ign.begin(), ign.end());
        if (cache) {
          for (auto& a : anns) e.anns.push_back({a.kind, a.va, a.name, a.flags, a.line});
          for (auto& ig : ign) e.ignored.push_back({ig.line, ig.text});
        }
      }
      if (cache) cache->keep(file, e);
    }
  }
  return out;
}

void check_duplicates(const std::vector<Annotation>& anns) {
  std::map<u64, std::pair<std::string, bool>> seen;
  for (auto& a : anns) {
    if (!is_paired(a.kind)) continue;
    bool folded = a.flags.folded;
    auto it = seen.find(a.va);
    if (it != seen.end() && !(folded && it->second.second)) {
      std::fprintf(stderr, "duplicate annotation %s: %s and %s:%d (mark /OPT:ICF folds FOLDED)\n", hex(a.va).c_str(),
                   it->second.first.c_str(), std::string(a.path).c_str(), a.line);
      std::exit(1);
    }
    seen[a.va] = {std::string(a.path) + ":" + std::to_string(a.line), folded};
  }
}

}  // namespace verifier

namespace verifier {

namespace {
constexpr std::string_view SOURCES_MAGIC = "verifier-sources 1\n";
template <class T>
void put(std::string& out, const T& v) { out.append(reinterpret_cast<const char*>(&v), sizeof v); }
void put_str(std::string& out, std::string_view s) { put(out, u32(s.size())); out += s; }
}  // namespace

SourceCache::SourceCache(std::string path, std::string key, i64 recent) : path_(std::move(path)), key_(std::move(key)), recent_(recent) {
  if (path_.empty() || !file_exists(path_)) return;
  std::string d;
  try { d = read_file(path_); } catch (...) { return; }
  std::string head = std::string(SOURCES_MAGIC) + key_ + "\n";
  if (d.compare(0, head.size(), head) != 0) return;
  size_t p = head.size();
  bool ok = true;
  auto get = [&](void* dst, size_t n) {
    if (!ok || p + n > d.size()) { ok = false; return; }
    std::memcpy(dst, d.data() + p, n);
    p += n;
  };
  auto str = [&](std::string& s) {
    u32 n = 0;
    get(&n, 4);
    if (!ok || p + n > d.size()) { ok = false; return; }
    s.assign(d, p, n);
    p += n;
  };
  std::unordered_map<std::string, Stored> m;
  while (ok && p < d.size()) {
    std::string file;
    Stored st{};
    str(file);
    get(&st.size, 8);
    get(&st.time, 8);
    str(st.e.hash);
    u32 na = 0, ni = 0;
    get(&na, 4);
    for (u32 i = 0; ok && i < na; ++i) {
      Ann a;
      u8 folded = 0, dtor = 0;
      str(a.kind);
      get(&a.va, 8);
      str(a.name);
      get(&folded, 1);
      get(&dtor, 1);
      str(a.flags.sig);
      get(&a.line, 4);
      a.flags.folded = folded;
      a.flags.dtor = dtor;
      st.e.anns.push_back(std::move(a));
    }
    get(&ni, 4);
    for (u32 i = 0; ok && i < ni; ++i) {
      Ign g;
      get(&g.line, 4);
      str(g.text);
      st.e.ignored.push_back(std::move(g));
    }
    if (ok) m.emplace(std::move(file), std::move(st));
  }
  if (ok) old_ = std::move(m);
}

const SourceCache::Entry* SourceCache::find(const ListedFile& f) const {
  auto it = old_.find(f.path);
  if (it == old_.end() || it->second.size != f.size || it->second.time != f.time || f.time >= recent_) {
    ++stats_.misses;
    return nullptr;
  }
  ++stats_.hits;
  return &it->second.e;
}

void SourceCache::keep(const ListedFile& f, const Entry& e) {
  auto it = old_.find(f.path);
  if (it == old_.end() || it->second.size != f.size || it->second.time != f.time || it->second.e.hash != e.hash) changed_ = true;
  new_.emplace_back(f, e);
}

void SourceCache::save() {
  if (path_.empty() || (!changed_ && new_.size() == old_.size())) return;
  std::string out = std::string(SOURCES_MAGIC) + key_ + "\n";
  for (auto& [f, e] : new_) {
    put_str(out, f.path);
    put(out, f.size);
    put(out, f.time);
    put_str(out, e.hash);
    put(out, u32(e.anns.size()));
    for (auto& a : e.anns) {
      put_str(out, a.kind);
      put(out, a.va);
      put_str(out, a.name);
      put(out, u8(a.flags.folded));
      put(out, u8(a.flags.dtor));
      put_str(out, a.flags.sig);
      put(out, i32(a.line));
    }
    put(out, u32(e.ignored.size()));
    for (auto& g : e.ignored) {
      put(out, i32(g.line));
      put_str(out, g.text);
    }
  }
  write_file_atomic(path_, out);
}

}  // namespace verifier
