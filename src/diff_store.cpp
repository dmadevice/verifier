#include "diff_store.hpp"

#include <algorithm>
#include <cstring>

#include "content_hash.hpp"

namespace verifier {

namespace {

constexpr std::string_view MAGIC = "verifier-diffs 1\n";

template <class T>
void put(std::string& out, const T& v) { out.append(reinterpret_cast<const char*>(&v), sizeof v); }
void put_str(std::string& out, std::string_view s) { put(out, u32(s.size())); out += s; }
void pad8(std::string& out) { out.append((8 - out.size() % 8) % 8, '\0'); }

// everything of a token the diff and the category read (as text where they show it)
void put_tok(std::string& out, const Tok& t) {
  put_str(out, t.mnemonic.str());
  put(out, u8(t.ops.size()));
  for (const Op& o : t.ops) {
    put(out, u8(o.k));
    put(out, o.v);
    put(out, o.base);
    put(out, o.index);
    put(out, o.seg);
    put(out, o.size);
    put(out, o.scale);
    put(out, u8(o.key.kind));
    put(out, o.key.va);
    if (o.key.kind == Key::IMP) put_str(out, imp_str(o.key.imp));
    else put_str(out, o.key.name);
  }
}

std::string entry_blob(const DiffStore::Entry& e) {
  std::string b;
  put_str(b, e.category);
  put(b, u32(e.diff.size()));
  for (auto& l : e.diff) put_str(b, l);
  return b;
}

bool read_entry(std::string_view b, DiffStore::Entry& e) {
  size_t p = 0;
  auto u32_at = [&](u32& v) {
    if (p + 4 > b.size()) return false;
    std::memcpy(&v, b.data() + p, 4);
    p += 4;
    return true;
  };
  auto str = [&](std::string& s) {
    u32 n;
    if (!u32_at(n) || p + n > b.size()) return false;
    s.assign(b.data() + p, n);
    p += n;
    return true;
  };
  u32 lines;
  if (!str(e.category) || !u32_at(lines) || lines > b.size()) return false;
  e.diff.resize(lines);
  for (auto& l : e.diff) if (!str(l)) return false;
  return p == b.size();
}

}  // namespace

DiffStore::DiffStore(std::string path, const std::string& key) : path_(std::move(path)), key_(key) {
  if (!path_.empty()) load();
}

void DiffStore::load() {
  try {
    if (!file_exists(path_)) return;
    file_ = std::make_unique<const MappedFile>(path_);
  } catch (...) {
    return;
  }
  std::string_view d = file_->view();
  std::string head = std::string(MAGIC) + key_ + "\n";
  size_t p = head.size() + (8 - head.size() % 8) % 8;
  u64 n = 0;
  if (d.substr(0, head.size()) != head || p + 8 > d.size()) { file_.reset(); return; }
  std::memcpy(&n, d.data() + p, 8);
  p += 8;
  if (n > d.size() / sizeof(Index) || p + n * sizeof(Index) > d.size()) { file_.reset(); return; }
  index_ = reinterpret_cast<const Index*>(d.data() + p);
  nindex_ = n;
  blobs_ = d.substr(p + n * sizeof(Index));
}

DiffStore::Entry DiffStore::get(const std::vector<u32>& o_off, const std::vector<u32>& r_off, const Toks& ot, const Toks& rt,
                                const NameOf& names) {
  auto make = [&] { return Entry{classify(ot, rt), insn_diff(o_off, r_off, ot, rt, names)}; };
  if (path_.empty()) return make();
  std::string s;
  s.reserve(64 * (ot.size() + rt.size()));
  put(s, u64(o_off.size()));
  s.append(reinterpret_cast<const char*>(o_off.data()), o_off.size() * 4);
  put(s, u64(r_off.size()));
  s.append(reinterpret_cast<const char*>(r_off.data()), r_off.size() * 4);
  put(s, u64(ot.size()));
  for (auto& t : ot) put_tok(s, t);
  put(s, u64(rt.size()));
  for (auto& t : rt) put_tok(s, t);
  std::pair<u64, u64> k{xxh64(s, 0), xxh64(s, 0x9E3779B185EBCA87ull)};
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
  std::string out = std::string(MAGIC) + key_ + "\n";
  pad8(out);
  put(out, u64(used_.size()));
  u64 off = 0;
  for (auto& [k, b] : used_) {
    put(out, Index{k.first, k.second, off, b.size()});
    off += b.size();
  }
  for (auto& [k, b] : used_) out += b;
  index_ = nullptr;
  nindex_ = 0;
  file_.reset();
  write_file_atomic(path_, out);
}

}  // namespace verifier
