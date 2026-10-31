#include "source_cache.hpp"

#include "cache_file.hpp"

namespace verifier {

namespace {

// the file: header; then for each file listed, in order: its path, size, time and content hash, its annotations (kind,
// address, name, FOLDED, destructor, parameter list, line) and the annotations naming nothing (line, text); strings as
// u32 length and bytes, counts as u32
constexpr std::string_view MAGIC = "verifier-sources 1\n";

}  // namespace

SourceCache::SourceCache(std::string path, std::string key, i64 recent) : path_(std::move(path)), key_(std::move(key)), recent_(recent) {
  std::string head = cache_header(MAGIC, key_);
  auto file = open_cache_file(path_, head);
  if (!file) return;
  BinReader r(file->view(), head.size());
  std::unordered_map<std::string, Stored> m;
  while (r.ok() && !r.done()) {
    std::string name;
    Stored st{};
    u32 na = 0, ni = 0;
    r.str(name);
    r.get(st.size);
    r.get(st.time);
    r.str(st.e.hash);
    r.get(na);
    for (u32 i = 0; r.ok() && i < na; ++i) {
      Ann a;
      u8 folded = 0, dtor = 0;
      r.str(a.kind);
      r.get(a.va);
      r.str(a.name);
      r.get(folded);
      r.get(dtor);
      r.str(a.flags.sig);
      r.get(a.line);
      a.flags.folded = folded;
      a.flags.dtor = dtor;
      st.e.anns.push_back(std::move(a));
    }
    r.get(ni);
    for (u32 i = 0; r.ok() && i < ni; ++i) {
      Ign g;
      r.get(g.line);
      r.str(g.text);
      st.e.ignored.push_back(std::move(g));
    }
    if (r.ok()) m.emplace(std::move(name), std::move(st));
  }
  if (r.ok()) old_ = std::move(m);   // a damaged file is not used at all
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
  BinWriter w;
  w.out = cache_header(MAGIC, key_);
  for (auto& [f, e] : new_) {
    w.str(f.path);
    w.put(f.size);
    w.put(f.time);
    w.str(e.hash);
    w.put(u32(e.anns.size()));
    for (auto& a : e.anns) {
      w.str(a.kind);
      w.put(a.va);
      w.str(a.name);
      w.put(u8(a.flags.folded));
      w.put(u8(a.flags.dtor));
      w.str(a.flags.sig);
      w.put(i32(a.line));
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
