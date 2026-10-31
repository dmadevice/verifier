#include "code_store.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>

#include "cache_file.hpp"
#include "content_hash.hpp"

namespace verifier {

namespace {

// the file: header, padding to 8; the mnemonics (u64 count, then each as u16 length and text), padding to 8; the
// index (u64 count, then Index records sorted by range); the entries, each 8-byte aligned: BlobHead, Lean[ninsns],
// padding to 8, Field[nfields], (i64 offset, i64 entry size)[ntables]. The arrays are copied out as they are.
constexpr std::string_view MAGIC = "verifier-code 2\n";

struct BlobHead {
  u8 relocated, complete, has_resume, pad[5];
  i64 cut, resume;
  u64 code_len;
  u32 ninsns, nfields, ntables, pad2;
};

}  // namespace

std::shared_ptr<const Code> CodeCache::code(u64 start, u64 end) {
  auto it = live_.find({start, end});
  if (it != live_.end()) return it->second;
  auto c = store_ ? store_->code(start, end) : std::make_shared<const Code>(*img_, start, end);
  return live_.emplace(std::make_pair(start, end), std::move(c)).first->second;
}

CodeStore::CodeStore(std::string path, const Image& img, const std::string& decoder)
    : path_(std::move(path)), img_(img) {
  key_ = "decoder " + decoder + " base " + hex(img.base) + " headers " + hex(xxh64(img.headers, 0));
  if (!path_.empty()) load();
}

void CodeStore::load() {
  std::string head = cache_header(MAGIC, key_);
  file_ = open_cache_file(path_, head);
  if (!file_) return;
  BinReader r(file_->view(), head.size());
  r.pad8();
  u64 nmnem = 0, n = 0;
  if (!r.get(nmnem) || nmnem > 0x10000) return fail();
  mnem_.resize(nmnem);
  for (auto& m : mnem_) {
    u16 len = 0;
    r.get(len);
    std::string_view text = r.take(len);
    if (!r.ok()) return fail();
    m = Mnem(text).id();
  }
  r.pad8();
  if (!r.get(n)) return fail();
  std::string_view index = r.take(n * sizeof(Index));  // used in place: 8-byte aligned (the file is mapped at a page)
  if (!r.ok()) return fail();
  index_ = reinterpret_cast<const Index*>(index.data());
  nindex_ = n;
  blobs_ = file_->view().substr(size_t(index.data() + index.size() - file_->view().data()));
}

void CodeStore::fail() {
  index_ = nullptr;
  nindex_ = 0;
  mnem_.clear();
  file_.reset();
}

u64 CodeStore::check(u64 start, u64 end) const {
  // the bytes (and the 8 after: a relocated quadword at the end is read whole), and the relocation sites in them
  std::string_view bytes = img_.bytes(start, i64(end - start) + 8);
  u64 h = xxh64(bytes, end - start);
  std::vector<u64> sites;
  for (size_t i = img_.reloc_lower_bound(start); i < img_.reloc_sorted.size() && img_.reloc_sorted[i] < end + 8; ++i)
    sites.push_back(img_.reloc_sorted[i] - start);
  return xxh64(std::string_view(reinterpret_cast<const char*>(sites.data()), sites.size() * 8), h);
}

std::string CodeStore::blob(const Code& c) const {
  BlobHead h{};
  h.relocated = c.relocated;
  h.complete = c.complete;
  h.has_resume = c.resume.has_value();
  h.cut = c.cut;
  h.resume = c.resume.value_or(0);
  h.code_len = c.code.size();
  h.ninsns = u32(c.insns.size());
  h.nfields = u32(c.field_list.size());
  h.ntables = u32(c.tables.size());
  BinWriter w;
  w.out.reserve(sizeof h + c.insns.size() * sizeof(Lean) + c.field_list.size() * sizeof(Field) + c.tables.size() * 16);
  w.put(h);
  w.array(c.insns.data(), c.insns.size());
  w.pad8();
  w.array(c.field_list.data(), c.field_list.size());
  for (auto& [off, size] : c.tables) {
    w.put(off);
    w.put(i64(size));
  }
  return std::move(w.out);
}

std::shared_ptr<const Code> CodeStore::from_blob(u64 start, u64 end, std::string_view b) const {
  BinReader r(b, 0);
  BlobHead h;
  if (!r.get(h)) return nullptr;
  std::shared_ptr<Code> c(new Code());
  c->img = &img_;
  c->start = start;
  c->end = end;
  c->decoded_from_ = img_.bytes(start, i64(end) - i64(start));
  c->code = c->decoded_from_.substr(0, std::min<size_t>(h.code_len, c->decoded_from_.size()));
  c->relocated = h.relocated;
  c->complete = h.complete;
  c->cut = h.cut;
  if (h.has_resume) c->resume = h.resume;
  std::string_view insns = r.take(h.ninsns * sizeof(Lean));
  r.pad8();
  std::string_view fields = r.take(h.nfields * sizeof(Field));
  if (!r.ok() || reinterpret_cast<uintptr_t>(b.data()) % 8) return nullptr;  // entries are 8-byte aligned in the file
  auto lean = reinterpret_cast<const Lean*>(insns.data());
  auto field = reinterpret_cast<const Field*>(fields.data());
  c->insns.assign(lean, lean + h.ninsns);
  for (auto& l : c->insns) {
    if (l.mnem >= mnem_.size()) return nullptr;
    l.mnem = mnem_[l.mnem];  // the file's numbering to this run's
  }
  c->field_list.assign(field, field + h.nfields);
  for (u32 i = 0; i < h.ntables; ++i) {
    i64 off = 0, size = 0;
    r.get(off);
    r.get(size);
    c->tables.emplace(off, int(size));
  }
  if (!r.ok() || !r.done()) return nullptr;
  return c;
}

std::shared_ptr<const Code> CodeStore::code(u64 start, u64 end) {
  if (path_.empty()) {
    ++stats_.misses;
    return std::make_shared<const Code>(img_, start, end);
  }
  auto k = std::make_pair(start, end);
  u64 ck = check(start, end);
  const Index* it = std::lower_bound(index_, index_ + nindex_, k, [](const Index& x, const std::pair<u64, u64>& y) {
    return std::make_pair(x.start, x.end) < y;
  });
  if (it != index_ + nindex_ && it->start == start && it->end == end && it->check == ck &&
      it->offset + it->size <= blobs_.size()) {
    if (auto c = from_blob(start, end, blobs_.substr(it->offset, it->size))) {
      ++stats_.hits;
      return c;
    }
  }
  auto c = std::make_shared<const Code>(img_, start, end);
  ++stats_.misses;
  decoded_[k] = {ck, blob(*c)};
  dirty_ = true;
  return c;
}

void CodeStore::save() {
  // rewritten when it has nothing usable or a twentieth of what was asked for was decoded here: a few functions it
  // lacks are decoded each run (microseconds) until there are enough to be worth writing the file again (milliseconds)
  if (path_.empty() || !dirty_ || (nindex_ && stats_.misses * 20 <= stats_.hits + stats_.misses)) return;
  auto t0 = std::chrono::steady_clock::now();
  // the functions decoded here, and the file's entries that still hold (made again from it in this run's mnemonic ids,
  // before it is replaced and its mapping released)
  std::map<std::pair<u64, u64>, std::pair<u64, std::string>> all = std::move(decoded_);
  for (size_t i = 0; i < nindex_; ++i) {
    const Index& x = index_[i];
    auto k = std::make_pair(x.start, x.end);
    if (all.count(k) || x.check != check(x.start, x.end) || x.offset + x.size > blobs_.size()) continue;
    if (auto c = from_blob(x.start, x.end, blobs_.substr(x.offset, x.size))) all[k] = {x.check, blob(*c)};
  }
  BinWriter w;
  w.out = cache_header(MAGIC, key_);
  w.pad8();
  w.put(u64(Mnem::count()));
  for (size_t i = 0; i < Mnem::count(); ++i) {
    std::string s = Mnem::from_id(u16(i)).str();
    w.put(u16(s.size()));
    w.out += s;
  }
  w.pad8();
  w.put(u64(all.size()));
  u64 off = 0;
  for (auto& [k, v] : all) {
    w.put(Index{k.first, k.second, v.first, off, v.second.size()});
    off += v.second.size();
  }
  for (auto& [k, v] : all) w.out += v.second;
  fail();  // the mapping released before the file is replaced
  write_cache_file(path_, w.out);
  if (std::getenv("VERIFIER_TIMING"))
    std::fprintf(stderr, "code store %s rewritten: %zu bytes, %.1f ms\n", path_.c_str(), w.out.size(),
                 std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count());
}

}  // namespace verifier
