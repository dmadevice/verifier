#include "annotations.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <limits>
#include <map>

#include "cache_file.hpp"
#include "names.hpp"

#ifdef _WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace verifier {

namespace {
constexpr std::string_view KIND_NAMES[] = {"FUNCTION", "STUB", "SYNTHETIC", "TEMPLATE", "LIBRARY", "GLOBAL", "VTABLE"};
}  // namespace

std::string_view kind_name(Kind k) { return KIND_NAMES[size_t(k)]; }

void set_keys(Annotation& a) {
  a.key = norm_name(a.kind == Kind::Vtable ? a.name + "::`vftable'" : a.name);
  if (a.key == a.name) a.key.clear();
  a.deleting_key = a.flags.dtor ? norm_name(deleting_destructor(a.name)) : std::string();
  a.keyed = true;
}

std::optional<Kind> kind_named(std::string_view name) {
  for (size_t i = 0; i < std::size(KIND_NAMES); ++i)
    if (KIND_NAMES[i] == name) return Kind(i);
  return std::nullopt;
}

std::optional<std::string> sig_flag(const AnnotationFlags& flags) {
  if (flags.sig.empty()) return std::nullopt;
  return flags.sig;
}

namespace {

// list_files, appending to out (a link to a directory is a file): on Windows the sizes and times come from the listing
// itself (FindFirstFileEx gives every entry's), elsewhere from a stat each
void walk(const std::string& root, std::vector<ListedFile>& out) {
  std::vector<ListedFile> files;  // by name, until joined to root
  std::vector<std::string> dirs;
#ifdef _WIN32
  WIN32_FIND_DATAW d;
  HANDLE h = FindFirstFileExW((std::filesystem::path(root) / L"*").c_str(), FindExInfoBasic, &d, FindExSearchNameMatch,
                              nullptr, FIND_FIRST_EX_LARGE_FETCH);
  if (h == INVALID_HANDLE_VALUE) return;  // no such directory
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
    f.time = e2 ? std::numeric_limits<i64>::max() : i64(time.time_since_epoch().count());  // unknown: recent
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

// `//\s*(FUNCTION|...):\s*<module>\s+0x([0-9a-fA-F]+)\s*(.*)$` anywhere in the line: kind, hex, rest
bool match_annotation(std::string_view line, const std::string& module, Kind& kind, std::string& hexs,
                      std::string& rest) {
  for (size_t p = line.find("//"); p != std::string_view::npos; p = line.find("//", p + 1)) {
    size_t i = p + 2;
    while (i < line.size() && is_space(line[i])) ++i;
    std::optional<Kind> k;
    for (size_t c = 0; c < std::size(KIND_NAMES); ++c) {
      std::string_view n = KIND_NAMES[c];
      if (line.compare(i, n.size(), n) == 0 && line.compare(i + n.size(), 1, ":") == 0) {
        k = Kind(c);
        break;
      }
    }
    if (!k) continue;
    i += kind_name(*k).size() + 1;
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
    kind = *k;
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
    Kind kind;
    std::string hexs, rest0;
    if (!match_annotation(lines[i], module, kind, hexs, rest0)) continue;
    u64 va = parse_hex(hexs);
    std::string rest = strip(rest0);
    AnnotationFlags flags;
    if (starts_with(rest, "FOLDED")) {
      flags.folded = true;
      rest = strip(rest.substr(6));
    }
    std::vector<std::string> following(lines.begin() + long(i) + 1,
                                       lines.begin() + long(std::min(lines.size(), i + 4)));
    size_t before = out.size();
    if (kind == Kind::Synthetic || kind == Kind::Template || kind == Kind::Library) {
      std::string name = rest;
      if (name.empty() && !following.empty()) {
        std::string f = strip(following[0]);
        size_t k = 0;
        while (k < f.size() && f[k] == '/') ++k;
        name = strip(f.substr(k));
      }
      long p = param_start(name);
      if (p > 0 && ends_with(name, ")")) {  // `Name(params)`: pairs with that overload only
        flags.sig = norm_params(name.substr(size_t(p)));
        name = strip(name.substr(0, size_t(p)));
      }
      out.push_back({kind, va, name, flags, kept_path, int(i + 1)});
      set_keys(out.back());
      continue;
    }
    if (starts_with(rest, "(") && ends_with(rest, ")")) flags.sig = norm_params(rest);
    if (kind == Kind::Global) {
      for (auto& nxt : following) {
        if (auto name = global_decl_name(nxt)) {
          out.push_back({kind, va, *name, flags, kept_path, int(i + 1)});
          break;
        }
      }
    } else if (kind == Kind::Vtable) {
      for (auto& nxt : following) {
        if (auto name = class_decl_name(nxt)) {
          out.push_back({kind, va, *name, flags, kept_path, int(i + 1)});
          break;
        }
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
    for (size_t k = before; k < out.size(); ++k) set_keys(out[k]);
  }
}

}  // namespace

std::vector<Annotation> parse_annotations(const std::vector<std::string>& roots, const std::string& module,
                                          std::vector<Ignored>* ignored, SourceCache* cache) {
  std::vector<Annotation> out;
  for (auto& root : roots) {
    for (auto& file : list_files(root)) {
      const std::string& path = file.path;
      bool source = ends_with(path, ".cpp") || ends_with(path, ".h") || ends_with(path, ".c") ||
                    ends_with(path, ".hpp") || ends_with(path, ".inl");
      if (!source) continue;
      if (const SourceCache::Entry* e = cache ? cache->find(file) : nullptr) {  // as the cache has it: not read
        std::string_view kept_path = keep_text(path);
        for (auto& a : e->anns)
          out.push_back({a.kind, a.va, a.name, a.flags, kept_path, a.line, true, a.key, a.deleting_key});
        if (ignored)
          for (auto& ig : e->ignored) ignored->push_back({path, ig.line, ig.text});
        cache->keep(file, e);
        continue;
      }
      std::string data = read_file(path);
      SourceCache::Entry e;
      if (data.find(module) != std::string::npos) {  // else no annotation of this module here
        std::vector<Annotation> anns;
        std::vector<Ignored> ign;
        parse_file(data, path, keep_text(path), module, anns, &ign);
        out.insert(out.end(), anns.begin(), anns.end());
        if (ignored) ignored->insert(ignored->end(), ign.begin(), ign.end());
        if (cache) {
          for (auto& a : anns) e.anns.push_back({a.kind, a.va, a.name, a.flags, a.line, a.key, a.deleting_key});
          for (auto& ig : ign) e.ignored.push_back({ig.line, ig.text});
        }
      }
      if (cache) cache->keep(file, std::move(e));
    }
  }
  return out;
}

// -- SourceCache --------------------------------------------------------------------------------------------------

namespace {

// the file: header; then for each source file listed, in order: its path, size and time, its annotations (kind,
// address, name, FOLDED, destructor, parameter list, line, the lookup keys: Annotation's) and the annotations naming
// nothing (line, text); strings as u32 length and bytes, counts as u32
constexpr std::string_view SOURCES_MAGIC = "verifier-sources 3\n";

}  // namespace

SourceCache::SourceCache(std::string path, std::string key, i64 recent)
    : path_(std::move(path)), key_(std::move(key)), recent_(recent) {
  std::string head = cache_header(SOURCES_MAGIC, key_);
  auto file = open_cache_file(path_, head);
  if (!file) return;
  BinReader r(file->view(), head.size());
  std::unordered_map<std::string, Stored> m;
  bool known_kinds = true;
  while (r.ok() && known_kinds && !r.done()) {
    std::string name;
    Stored st{};
    u32 na = 0, ni = 0;
    r.str(name);
    r.get(st.size);
    r.get(st.time);
    r.get(na);
    for (u32 i = 0; r.ok() && i < na; ++i) {
      Entry::Ann a;
      u8 kind = 0, folded = 0, dtor = 0;
      r.get(kind);
      if (kind > u8(Kind::Vtable)) known_kinds = false;
      a.kind = Kind(kind);
      r.get(a.va);
      r.str(a.name);
      r.get(folded);
      r.get(dtor);
      r.str(a.flags.sig);
      r.get(a.line);
      r.str(a.key);
      r.str(a.deleting_key);
      a.flags.folded = folded;
      a.flags.dtor = dtor;
      st.e.anns.push_back(std::move(a));
    }
    r.get(ni);
    for (u32 i = 0; r.ok() && i < ni; ++i) {
      Entry::Ign g;
      r.get(g.line);
      r.str(g.text);
      st.e.ignored.push_back(std::move(g));
    }
    if (r.ok()) m.emplace(std::move(name), std::move(st));
  }
  if (r.ok() && known_kinds) old_ = std::move(m);  // a damaged file is not used at all
}

const SourceCache::Entry* SourceCache::find(const ListedFile& f) const {
  auto it = old_.find(f.path);
  if (it == old_.end() || it->second.size != f.size || it->second.time != f.time || f.time >= recent_) return nullptr;
  return &it->second.e;
}

void SourceCache::keep(const ListedFile& f, Entry e) {
  if (f.time >= recent_) {  // changed too recently for its stamp to show a later change: not kept
    changed_ = true;
    return;
  }
  auto it = old_.find(f.path);
  if (it == old_.end() || it->second.size != f.size || it->second.time != f.time) changed_ = true;
  new_.emplace_back(f, &made_.emplace_back(std::move(e)));
}

void SourceCache::keep(const ListedFile& f, const Entry* found) { new_.emplace_back(f, found); }

void SourceCache::save() {
  if (path_.empty() || (!changed_ && new_.size() == old_.size())) return;
  BinWriter w;
  w.out = cache_header(SOURCES_MAGIC, key_);
  for (auto& [f, ep] : new_) {
    const Entry& e = *ep;
    w.str(f.path);
    w.put(f.size);
    w.put(f.time);
    w.put(u32(e.anns.size()));
    for (auto& a : e.anns) {
      w.put(u8(a.kind));
      w.put(a.va);
      w.str(a.name);
      w.put(u8(a.flags.folded));
      w.put(u8(a.flags.dtor));
      w.str(a.flags.sig);
      w.put(i32(a.line));
      w.str(a.key);
      w.str(a.deleting_key);
    }
    w.put(u32(e.ignored.size()));
    for (auto& g : e.ignored) {
      w.put(i32(g.line));
      w.str(g.text);
    }
  }
  write_cache_file(path_, w.out);
}

}  // namespace verifier
