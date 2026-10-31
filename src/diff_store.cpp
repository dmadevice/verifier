#include "diff_store.hpp"

#include <algorithm>

#include "cache_file.hpp"
#include "content_hash.hpp"

namespace verifier {

namespace {

// the file: header, padding to 8; the index (u64 count, then Index records sorted by key); the entries, each: the
// category and the diff's line count and lines (strings as u32 length and bytes)
constexpr std::string_view MAGIC = "verifier-diffs 1\n";

// The key: two 64-bit hashes run over everything of the tokens the diff and the category read (the instructions'
// offsets; per token its mnemonic's text and per operand its fields and its key's text, the import's name for an
// import), without writing it out first (a function's tokens are tens of kilobytes).
class KeyHash {
 public:
  void add(u64 x) {
    a_ = rotl(a_ ^ (x * P2), 31) * P1;
    b_ = rotl(b_ + x * P3, 27) * P4 + (b_ >> 29);
  }
  void add(std::string_view s) {
    add(u64(s.size()));
    add(xxh64(s, 0x5bd1e995));
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

void add_tok(KeyHash& h, const Tok& t) {
  h.add(std::string_view(t.mnemonic.str()));
  h.add(u64(t.ops.size()));
  for (const Op& o : t.ops) {
    h.add(u64(o.k) | u64(o.scale) << 8 | u64(o.key.kind) << 16 | u64(o.size) << 32 | u64(o.seg) << 48);
    h.add(u64(o.base) | u64(o.index) << 16);
    h.add(u64(o.v));
    h.add(o.key.va);
    if (o.key.kind == Key::IMP) {
      std::string name = imp_str(o.key.imp);
      h.add(std::string_view(name));
    } else {
      h.add(o.key.name);
    }
  }
}

std::string entry_blob(const DiffStore::Entry& e) {
  BinWriter w;
  w.str(e.category);
  w.put(u32(e.diff.size()));
  for (auto& l : e.diff) w.str(l);
  return std::move(w.out);
}

bool read_entry(std::string_view b, DiffStore::Entry& e) {
  BinReader r(b, 0);
  u32 lines = 0;
  if (!r.str(e.category) || !r.get(lines) || lines > b.size()) return false;
  e.diff.resize(lines);
  for (auto& l : e.diff) r.str(l);
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
  r.pad8();
  u64 n = 0;
  r.get(n);
  std::string_view index = r.take(n * sizeof(Index));  // used in place: 8-byte aligned (the file is mapped at a page)
  if (!r.ok() || n > file_->view().size() / sizeof(Index)) {
    file_.reset();
    return;
  }
  index_ = reinterpret_cast<const Index*>(index.data());
  nindex_ = n;
  blobs_ = file_->view().substr(size_t(index.data() + index.size() - file_->view().data()));
}

DiffStore::Entry DiffStore::get(const std::vector<u32>& o_off, const std::vector<u32>& r_off, const Toks& ot,
                                const Toks& rt, const NameOf& names) {
  auto make = [&] { return Entry{classify(ot, rt), insn_diff(o_off, r_off, ot, rt, names)}; };
  if (path_.empty()) return make();
  KeyHash h;
  h.add(u64(o_off.size()));
  for (u32 x : o_off) h.add(u64(x));
  h.add(u64(r_off.size()));
  for (u32 x : r_off) h.add(u64(x));
  h.add(u64(ot.size()));
  for (auto& t : ot) add_tok(h, t);
  h.add(u64(rt.size()));
  for (auto& t : rt) add_tok(h, t);
  std::pair<u64, u64> k = h.done();
  if (auto u = used_.find(k); u != used_.end()) {
    Entry e;
    if (read_entry(u->second.blob(), e)) return e;
  }
  const Index* it = std::lower_bound(index_, index_ + nindex_, k, [](const Index& x, const std::pair<u64, u64>& y) {
    return std::make_pair(x.k0, x.k1) < y;
  });
  if (it != index_ + nindex_ && it->k0 == k.first && it->k1 == k.second && it->offset + it->size <= blobs_.size()) {
    Entry e;
    std::string_view b = blobs_.substr(it->offset, it->size);
    if (read_entry(b, e)) {
      ++stats_.hits;
      used_.emplace(k, Used{std::string(), b});
      return e;
    }
  }
  ++stats_.misses;
  Entry e = make();
  used_.emplace(k, Used{entry_blob(e), std::string_view()});
  return e;
}

void DiffStore::save() {
  if (path_.empty() || (!stats_.misses && used_.size() == nindex_)) return;  // as it was
  BinWriter w;
  w.out = cache_header(MAGIC, key_);
  w.pad8();
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
