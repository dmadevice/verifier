#include "diff_store.hpp"

#include <algorithm>

#include "cache_file.hpp"
#include "content_hash.hpp"

namespace verifier {

namespace {

// the file: header, padding to 8; the index (u64 count, then Index records sorted by key); the entries, each: the
// category and the diff's line count and lines (strings as u32 length and bytes)
constexpr std::string_view MAGIC = "verifier-diffs 1\n";

// everything of a token the diff and the category read (as text where they show it)
void put_tok(BinWriter& w, const Tok& t) {
  w.str(t.mnemonic.str());
  w.put(u8(t.ops.size()));
  for (const Op& o : t.ops) {
    w.put(u8(o.k));
    w.put(o.v);
    w.put(o.base);
    w.put(o.index);
    w.put(o.seg);
    w.put(o.size);
    w.put(o.scale);
    w.put(u8(o.key.kind));
    w.put(o.key.va);
    if (o.key.kind == Key::IMP) w.str(imp_str(o.key.imp));
    else w.str(o.key.name);
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
  std::string_view index = r.take(n * sizeof(Index));   // used in place: 8-byte aligned (the file is mapped at a page)
  if (!r.ok() || n > file_->view().size() / sizeof(Index)) { file_.reset(); return; }
  index_ = reinterpret_cast<const Index*>(index.data());
  nindex_ = n;
  blobs_ = file_->view().substr(size_t(index.data() + index.size() - file_->view().data()));
}

DiffStore::Entry DiffStore::get(const std::vector<u32>& o_off, const std::vector<u32>& r_off, const Toks& ot, const Toks& rt,
                                const NameOf& names) {
  auto make = [&] { return Entry{classify(ot, rt), insn_diff(o_off, r_off, ot, rt, names)}; };
  if (path_.empty()) return make();
  BinWriter w;   // what the key is a hash of
  w.out.reserve(64 * (ot.size() + rt.size()));
  w.put(u64(o_off.size()));
  w.array(o_off.data(), o_off.size());
  w.put(u64(r_off.size()));
  w.array(r_off.data(), r_off.size());
  w.put(u64(ot.size()));
  for (auto& t : ot) put_tok(w, t);
  w.put(u64(rt.size()));
  for (auto& t : rt) put_tok(w, t);
  std::pair<u64, u64> k{xxh64(w.out, 0), xxh64(w.out, 0x9E3779B185EBCA87ull)};
  if (auto u = used_.find(k); u != used_.end()) {
    Entry e;
    if (read_entry(u->second, e)) return e;
  }
  const Index* it = std::lower_bound(index_, index_ + nindex_, k, [](const Index& x, const std::pair<u64, u64>& y) {
    return std::make_pair(x.k0, x.k1) < y;
  });
  if (it != index_ + nindex_ && it->k0 == k.first && it->k1 == k.second && it->offset + it->size <= blobs_.size()) {
    Entry e;
    std::string_view b = blobs_.substr(it->offset, it->size);
    if (read_entry(b, e)) {
      ++stats_.hits;
      used_.emplace(k, std::string(b));
      return e;
    }
  }
  ++stats_.misses;
  Entry e = make();
  used_.emplace(k, entry_blob(e));
  return e;
}

void DiffStore::save() {
  if (path_.empty() || (!stats_.misses && used_.size() == nindex_)) return;   // as it was
  BinWriter w;
  w.out = cache_header(MAGIC, key_);
  w.pad8();
  w.put(u64(used_.size()));
  u64 off = 0;
  for (auto& [k, b] : used_) {
    w.put(Index{k.first, k.second, off, b.size()});
    off += b.size();
  }
  for (auto& [k, b] : used_) w.out += b;
  index_ = nullptr;
  nindex_ = 0;
  file_.reset();   // the mapping released before the file is replaced
  write_cache_file(path_, w.out);
}

}  // namespace verifier
