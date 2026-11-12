#include "diff_store.hpp"

#include <algorithm>
#include <cstring>
#include <stdexcept>

#include "cache_file.hpp"

namespace verifier {

namespace {

// the file: header, padding to 8; the index (u64 count, then Index records sorted by key); the entries
constexpr std::string_view MAGIC = "verifier-diffs 2\n";

// two 64-bit lanes over words; strings by length and their bytes in 8-byte words
class KeyHash {
 public:
  void add(u64 x) {
    a_ = rotl(a_ ^ (x * P2), 31) * P1;
    b_ = rotl(b_ + x * P3, 27) * P4 + (b_ >> 29);
  }
  void add(std::string_view s) {
    add(u64(s.size()));
    size_t i = 0;
    for (; i + 8 <= s.size(); i += 8) {
      u64 w;
      std::memcpy(&w, s.data() + i, 8);
      add(w);
    }
    u64 w = 0;
    std::memcpy(&w, s.data() + i, s.size() - i);
    add(w);
  }
  std::pair<u64, u64> done() const { return {avalanche(a_), avalanche(b_ ^ 0x9e3779b97f4a7c15ull)}; }

 private:
  static constexpr u64 P1 = 0x9E3779B185EBCA87ull, P2 = 0xC2B2AE3D27D4EB4Full, P3 = 0x165667B19E3779F9ull,
                       P4 = 0x85EBCA77C2B2AE63ull;
  static u64 rotl(u64 x, int r) { return (x << r) | (x >> (64 - r)); }
  static u64 avalanche(u64 h) {
    h ^= h >> 33;
    h *= P2;
    h ^= h >> 29;
    h *= P3;
    return h ^ (h >> 32);
  }
  u64 a_ = 0x243f6a8885a308d3ull, b_ = 0x13198a2e03707344ull;
};

std::pair<u64, u64> entry_key(const Code& oc, const Code& rc, const DiffContext& cx) {
  KeyHash h;
  h.add(oc.start);
  h.add(oc.end);
  h.add(oc.code);
  h.add(rc.start);
  h.add(rc.end);
  h.add(rc.code);
  h.add(std::string_view(reinterpret_cast<const char*>(rc.field_list.data()), rc.field_list.size_bytes()));
  h.add(rebuilt_targets(oc, rc, cx));
  // what the tokens show of each target: what its name resolves to, a compiler constant's bytes
  for (auto& f : rc.field_list) {
    if (f.kind == F_TBL) continue;
    u64 t = u64(f.value);
    if (auto it = rc.img->imports.find(t); it != rc.img->imports.end()) {
      h.add(imp_str(&it->second));
      continue;
    }
    Key k = cx.resolve(t);
    h.add(u64(k.kind));
    h.add(k.va);
    h.add(k.name);
    if (k.kind == Key::CONST) h.add(rc.img->bytes(t, 32));
  }
  return h.done();
}

std::string entry_blob(const DiffReport& e) {
  BinWriter w;
  w.put(u8(e.category ? 1 + u8(*e.category) : 0));
  w.put(u8(e.diff.differs));
  w.put(u8(e.diff.first.has_value()));
  w.put(u64(e.diff.first ? e.diff.first->first : 0));
  w.put(u64(e.diff.first ? e.diff.first->second : 0));
  w.str(e.first_orig);
  w.str(e.first_rebuilt);
  w.put(u32(e.diff.lines.size()));
  for (auto& l : e.diff.lines) w.str(l);
  return std::move(w.out);
}

bool read_entry(std::string_view b, DiffReport& e) {
  BinReader r(b, 0);
  u8 cat = 0, differs = 0, first = 0;
  u64 i = 0, j = 0;
  u32 lines = 0;
  r.get(cat);
  r.get(differs);
  r.get(first);
  r.get(i);
  r.get(j);
  r.str(e.first_orig);
  r.str(e.first_rebuilt);
  if (!r.get(lines) || lines > b.size()) return false;
  if (cat) e.category = Category(cat - 1);
  e.diff.differs = differs;
  if (first) e.diff.first = {size_t(i), size_t(j)};
  e.diff.lines.resize(lines);
  for (auto& l : e.diff.lines) r.str(l);
  return r.ok() && r.done();
}

}  // namespace

DiffStore::DiffStore(std::string path, const std::string& key) : path_(std::move(path)), key_(key) {
  if (!path_.empty()) load();
}

void DiffStore::load() {
  std::string head = cache_header(MAGIC, key_);
  file_ = open_cache_file(path_, head);
  if (!file_) return;
  BinReader r(file_->view(), head.size());
  r.take((8 - head.size() % 8) % 8);
  u64 n = 0;
  r.get(n);
  if (!r.ok() || n > file_->view().size() / sizeof(Index)) {
    file_.reset();
    return;
  }
  std::string_view index = r.take(n * sizeof(Index));  // used in place: 8-byte aligned (the file is mapped at a page)
  if (!r.ok()) {
    file_.reset();
    return;
  }
  index_ = reinterpret_cast<const Index*>(index.data());
  nindex_ = n;
  blobs_ = file_->view().substr(r.at());
}

DiffReport DiffStore::get(const Code& oc, const Code& rc, const DiffContext& cx,
                          const std::function<DiffReport()>& make) {
  if (path_.empty()) return make();
  std::pair<u64, u64> k = entry_key(oc, rc, cx);
  auto kept = [&](std::string_view b) -> std::optional<DiffReport> {
    DiffReport e;
    if (!read_entry(b, e)) return std::nullopt;
    if (check && !(make() == e)) throw std::runtime_error("diff store: a kept report differs from the one made");
    return e;
  };
  if (auto u = used_.find(k); u != used_.end())
    if (auto e = kept(u->second.blob())) return *e;
  const Index* it = std::lower_bound(index_, index_ + nindex_, k, [](const Index& x, const std::pair<u64, u64>& y) {
    return std::make_pair(x.k0, x.k1) < y;
  });
  if (it != index_ + nindex_ && it->k0 == k.first && it->k1 == k.second && it->offset + it->size <= blobs_.size()) {
    std::string_view b = blobs_.substr(it->offset, it->size);
    if (auto e = kept(b)) {
      ++stats_.hits;
      used_.emplace(k, Used{std::string(), b});
      return *e;
    }
  }
  ++stats_.misses;
  DiffReport e = make();
  used_.emplace(k, Used{entry_blob(e), std::string_view()});
  return e;
}

void DiffStore::save() {
  if (path_.empty() || (!stats_.misses && used_.size() == nindex_)) return;  // as it was
  BinWriter w;
  w.out = cache_header(MAGIC, key_);
  w.out.append((8 - w.out.size() % 8) % 8, '\0');
  w.put(u64(used_.size()));
  u64 off = 0;
  for (auto& [k, u] : used_) {
    w.put(Index{k.first, k.second, off, u.blob().size()});
    off += u.blob().size();
  }
  for (auto& [k, u] : used_) w.out += u.blob();  // the file's entries copied before its mapping is released
  index_ = nullptr;
  nindex_ = 0;
  file_.reset();  // the mapping released before the file is replaced
  write_cache_file(path_, w.out);
}

}  // namespace verifier
