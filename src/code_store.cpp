#include "code_store.hpp"

#include <algorithm>
#include <cstring>

#include <chrono>
#include <cstdio>
#include <cstdlib>

#include "content_hash.hpp"

namespace verifier {

namespace {

constexpr std::string_view MAGIC = "verifier-code 1\n";

struct BlobHead {   // then Lean[ninsns], Field[nfields], (i64 offset, i64 size)[ntables]
  u8 relocated, complete, has_resume, pad[5];
  i64 cut, resume;
  u64 code_len;
  u32 ninsns, nfields, ntables, pad2;
};

template <class T>
void put(std::string& out, const T& v) { out.append(reinterpret_cast<const char*>(&v), sizeof v); }
void pad8(std::string& out) { out.append((8 - out.size() % 8) % 8, '\0'); }

}  // namespace

CodeStore::CodeStore(std::string path, const Image& img, const std::string& decoder, bool keep_unused)
    : path_(std::move(path)), img_(img), keep_unused_(keep_unused) {
  key_ = "decoder " + decoder + " base " + hex(img.base) + " headers " + hex(xxh64(img.headers, 0));
  if (!path_.empty()) load();
}

void CodeStore::load() {
  try {
    if (!file_exists(path_)) return;
    file_ = std::make_unique<const MappedFile>(path_);
  } catch (...) {
    return;
  }
  std::string_view d = file_->view();
  std::string head = std::string(MAGIC) + key_ + "\n";
  auto fail = [&] { index_ = nullptr; nindex_ = 0; mnem_.clear(); file_.reset(); };
  if (d.substr(0, head.size()) != head) return fail();
  size_t p = head.size();
  p += (8 - p % 8) % 8;
  auto get = [&](void* dst, size_t n) {
    if (p + n > d.size()) return false;
    std::memcpy(dst, d.data() + p, n);
    p += n;
    return true;
  };
  u64 nmnem = 0;
  if (!get(&nmnem, 8) || nmnem > 0x10000) return fail();
  mnem_.resize(nmnem);
  for (u64 i = 0; i < nmnem; ++i) {
    u16 len = 0;
    if (!get(&len, 2) || p + len > d.size()) return fail();
    mnem_[i] = Mnem(d.substr(p, len)).id();
    p += len;
  }
  p += (8 - p % 8) % 8;
  u64 n = 0;
  if (!get(&n, 8) || p + n * sizeof(Index) > d.size()) return fail();
  index_ = reinterpret_cast<const Index*>(d.data() + p);   // 8-byte aligned: the file is mapped at a page
  nindex_ = n;
  blobs_ = d.substr(p + n * sizeof(Index));
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
  std::string out;
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
  out.reserve(sizeof h + c.insns.size() * sizeof(Lean) + c.field_list.size() * sizeof(Field) + c.tables.size() * 16);
  put(out, h);
  out.append(reinterpret_cast<const char*>(c.insns.data()), c.insns.size() * sizeof(Lean));
  out.append(reinterpret_cast<const char*>(c.field_list.data()), c.field_list.size() * sizeof(Field));
  for (auto& [off, size] : c.tables) { put(out, off); put(out, i64(size)); }
  return out;
}

std::shared_ptr<const Code> CodeStore::code(u64 start, u64 end) {
  u64 ck = 0;
  if (!path_.empty()) {
    ck = check(start, end);
    const Index* it = std::lower_bound(index_, index_ + nindex_, std::make_pair(start, end), [](const Index& x, const std::pair<u64, u64>& k) {
      return std::make_pair(x.start, x.end) < k;
    });
    if (it != index_ + nindex_ && it->start == start && it->end == end && it->check == ck && it->offset + it->size <= blobs_.size()) {
      std::string_view b = blobs_.substr(it->offset, it->size);
      BlobHead h;
      std::memcpy(&h, b.data(), sizeof h);
      size_t need = sizeof h + h.ninsns * sizeof(Lean) + h.nfields * sizeof(Field) + size_t(h.ntables) * 16;
      if (need == b.size()) {
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
        const char* p = b.data() + sizeof h;
        c->insns.resize(h.ninsns);
        std::memcpy(c->insns.data(), p, h.ninsns * sizeof(Lean));
        p += h.ninsns * sizeof(Lean);
        bool ok = true;
        for (auto& l : c->insns) {
          if (l.mnem >= mnem_.size()) { ok = false; break; }
          l.mnem = mnem_[l.mnem];
        }
        c->field_list.resize(h.nfields);
        std::memcpy(c->field_list.data(), p, h.nfields * sizeof(Field));
        p += h.nfields * sizeof(Field);
        for (u32 i = 0; i < h.ntables; ++i, p += 16) {
          i64 off, size;
          std::memcpy(&off, p, 8);
          std::memcpy(&size, p + 8, 8);
          c->tables.emplace(off, int(size));
        }
        if (ok) {
          ++stats_.hits;
          auto k = std::make_pair(start, end);
          if (!out_.count(k)) { out_.emplace(k, std::string()); checks_[k] = ck; }   // written from the Code at save
          return c;
        }
      }
    }
  }
  auto c = std::make_shared<const Code>(img_, start, end);
  ++stats_.misses;
  if (!path_.empty()) {
    auto k = std::make_pair(start, end);
    out_[k] = blob(*c);
    checks_[k] = ck;
    dirty_ = true;
  }
  return c;
}

void CodeStore::save() {
  // rewritten when it has nothing usable or a twentieth of what was asked for was decoded here: a few functions it
  // lacks are decoded each run (microseconds) until there are enough to be worth writing the file again (milliseconds)
  if (path_.empty() || !dirty_ || (nindex_ && stats_.misses * 20 <= stats_.hits + stats_.misses)) return;
  // every function written in this run's mnemonic ids: the ones read from the file are made again from it first
  // (before it is replaced, and its mapping released)
  auto t0 = std::chrono::steady_clock::now();
  std::map<std::pair<u64, u64>, std::pair<u64, std::string>> all;
  auto from_file = [&](const Index& x) { return blob(*code(x.start, x.end)); };
  for (auto& [k, b] : out_) all[k] = {checks_[k], b};
  for (auto& [k, v] : all)
    if (v.second.empty()) v.second = from_file(Index{k.first, k.second, 0, 0, 0});
  if (keep_unused_)
    for (size_t i = 0; i < nindex_; ++i) {
      const Index& x = index_[i];
      auto k = std::make_pair(x.start, x.end);
      if (all.count(k) || x.check != check(x.start, x.end)) continue;
      all[k] = {x.check, from_file(x)};
    }
  std::string out = std::string(MAGIC) + key_ + "\n";
  pad8(out);
  u64 nmnem = Mnem::count();
  put(out, nmnem);
  for (u64 i = 0; i < nmnem; ++i) {
    std::string s = Mnem::from_id(u16(i)).str();
    put(out, u16(s.size()));
    out += s;
  }
  pad8(out);
  put(out, u64(all.size()));
  u64 off = 0;
  for (auto& [k, v] : all) {
    put(out, Index{k.first, k.second, v.first, off, v.second.size()});
    off += v.second.size();
  }
  for (auto& [k, v] : all) out += v.second;
  index_ = nullptr;
  nindex_ = 0;
  file_.reset();
  write_file_atomic(path_, out);
  if (std::getenv("VERIFIER_TIMING"))
    std::fprintf(stderr, "code store %s rewritten: %zu bytes, %.1f ms\n", path_.c_str(), out.size(),
                 std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count());
}

}  // namespace verifier
