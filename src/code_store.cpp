#include "code_store.hpp"

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <string_view>

namespace verifier {

namespace {

// The file: its header; the mnemonics (u32 count, then each as a string, numbered from 0); then each function: its
// head (below), zeros to a multiple of 8 bytes from the start of the file, then its instructions, fields, switch tables
// (offset i64, entry size i32) and the shape's indexed displacements, as Code holds them. The instructions and fields
// are used in place when the run numbers the mnemonics as the file does.
constexpr std::string_view CODE_MAGIC = "verifier-code 2\n";
enum : u8 { COMPLETE = 1, RESUMES = 2, SHAPE_KNOWN = 4, ENDS_IN_JUMP = 8 };

struct Head {
  u64 start = 0, end = 0, size = 0;  // size: the code's, padding trimmed
  i64 cut = 0, resume = 0, reach = 0;
  u8 flags = 0;
  u32 insns = 0, fields = 0, tables = 0, indexed = 0;
  size_t rest() const {  // the bytes after the instructions and fields
    return tables * (sizeof(i64) + sizeof(i32)) + indexed * sizeof(i64);
  }
};

void put_head(BinWriter& w, const Head& h) {
  for (u64 v : {h.start, h.end, h.size}) w.put(v);
  for (i64 v : {h.cut, h.resume, h.reach}) w.put(v);
  w.put(h.flags);
  for (u32 v : {h.insns, h.fields, h.tables, h.indexed}) w.put(v);
  w.out.resize((w.out.size() + 7) & ~size_t(7), '\0');
}

bool get_head(BinReader& r, Head& h) {
  for (u64* v : {&h.start, &h.end, &h.size}) r.get(*v);
  for (i64* v : {&h.cut, &h.resume, &h.reach}) r.get(*v);
  r.get(h.flags);
  for (u32* v : {&h.insns, &h.fields, &h.tables, &h.indexed}) r.get(*v);
  r.take(((r.at() + 7) & ~size_t(7)) - r.at());
  return r.ok();
}

void put_code(BinWriter& w, const Code& c) {
  Head h;
  h.start = c.start;
  h.end = c.end;
  h.size = c.code.size();
  h.cut = c.cut;
  h.resume = c.resume.value_or(0);
  h.reach = c.shape.reach;
  h.flags = u8((c.complete ? COMPLETE : 0) | (c.resume ? RESUMES : 0) | (c.shape.known ? SHAPE_KNOWN : 0) |
               (c.shape.ends_in_jump ? ENDS_IN_JUMP : 0));
  h.insns = u32(c.insns.size());
  h.fields = u32(c.field_list.size());
  h.tables = u32(c.tables.size());
  h.indexed = u32(c.shape.indexed.size());
  put_head(w, h);
  w.array(c.insns.data(), c.insns.size());
  w.array(c.field_list.data(), c.field_list.size());
  for (auto& [t, size] : c.tables) {
    w.put(i64(t));
    w.put(i32(size));
  }
  w.array(c.shape.indexed.data(), c.shape.indexed.size());
}

// a record's instructions and fields, in the buffer read
struct Arrays {
  std::string_view insns, fields;
};
bool get_arrays(BinReader& r, const Head& h, Arrays& a) {
  a.insns = r.take(size_t(h.insns) * sizeof(Lean));
  a.fields = r.take(size_t(h.fields) * sizeof(Field));
  return r.ok();
}

// a function's record from one buffer to another, its mnemonics renumbered (false: one the table does not have)
bool copy_record(BinReader& r, BinWriter& w, const std::vector<u16>& mnems) {
  Head h;
  Arrays a;
  if (!get_head(r, h) || !get_arrays(r, h, a)) return false;
  std::vector<Lean> insns(h.insns);
  if (h.insns) std::memcpy(insns.data(), a.insns.data(), a.insns.size());
  for (Lean& l : insns) {
    if (l.mnem >= mnems.size()) return false;
    l.mnem = mnems[l.mnem];
  }
  std::string_view rest = r.take(h.rest());
  if (!r.ok()) return false;
  put_head(w, h);
  w.array(insns.data(), insns.size());
  w.out += a.fields;
  w.out += rest;
  return true;
}

}  // namespace

CodeStore::CodeStore(std::string path, std::string key) : path_(std::move(path)), key_(std::move(key)) {
  std::string head = cache_header(CODE_MAGIC, key_);
  file_ = open_cache_file(path_, head);
  if (!file_) return;
  BinReader r(file_->view(), head.size());
  u32 n = 0;
  r.get(n);
  for (u32 i = 0; r.ok() && i < n; ++i) {
    std::string s;
    if (r.str(s)) mnems_.push_back(Mnem(s).id());
  }
  in_place_ = true;
  for (size_t i = 0; i < mnems_.size(); ++i) in_place_ = in_place_ && mnems_[i] == i;
  while (r.ok() && !r.done()) {
    size_t at = r.at();
    Head h;
    Arrays a;
    if (get_head(r, h) && get_arrays(r, h, a)) r.take(h.rest());
    index_.push_back({h.start, h.end, at});
  }
  if (!r.ok()) {  // a damaged file is not used
    index_.clear();
    file_.reset();
    return;
  }
  std::sort(index_.begin(), index_.end());
}

std::shared_ptr<const Code> CodeStore::find(const Image& img, u64 start, u64 end) const {
  auto it = std::lower_bound(index_.begin(), index_.end(), Record{start, end, 0});
  if (it == index_.end() || it->start != start || it->end != end) return nullptr;
  BinReader r(file_->view(), it->at);
  Head h;
  Arrays a;
  get_head(r, h);
  get_arrays(r, h, a);
  std::shared_ptr<Code> c(new Code(img, start, end, Code::Undecoded{}));
  if (h.size > c->code.size()) return nullptr;
  c->code = c->code.substr(0, size_t(h.size));
  if (in_place_) {
    c->owner_ = file_;
    c->insns = {reinterpret_cast<const Lean*>(a.insns.data()), h.insns};
    c->field_list = {reinterpret_cast<const Field*>(a.fields.data()), h.fields};
  } else {
    c->lean_.resize(h.insns);
    c->fields_.resize(h.fields);
    if (h.insns) std::memcpy(c->lean_.data(), a.insns.data(), a.insns.size());
    if (h.fields) std::memcpy(c->fields_.data(), a.fields.data(), a.fields.size());
    for (Lean& l : c->lean_) {
      if (l.mnem >= mnems_.size()) return nullptr;
      l.mnem = mnems_[l.mnem];
    }
    c->insns = c->lean_;
    c->field_list = c->fields_;
  }
  for (u32 i = 0; i < h.tables; ++i) {
    i64 t = 0;
    i32 size = 0;
    r.get(t);
    r.get(size);
    c->tables[t] = size;
  }
  std::string_view indexed = r.take(size_t(h.indexed) * sizeof(i64));
  if (!r.ok()) return nullptr;
  c->shape.indexed.resize(h.indexed);
  if (h.indexed) std::memcpy(c->shape.indexed.data(), indexed.data(), indexed.size());
  c->cut = h.cut;
  if (h.flags & RESUMES) c->resume = h.resume;
  c->complete = h.flags & COMPLETE;
  c->shape.known = h.flags & SHAPE_KNOWN;
  c->shape.ends_in_jump = h.flags & ENDS_IN_JUMP;
  c->shape.reach = h.reach;
  return c;
}

void CodeStore::add(const Code& c) {
  if (!path_.empty()) put_code(added_, c);
}

void CodeStore::save() {
  // nothing new; or functions read in place still held, which keep the file open (it cannot be replaced then)
  if (path_.empty() || added_.out.empty() || file_.use_count() > 1) return;
  BinWriter w;
  w.out = cache_header(CODE_MAGIC, key_);
  w.put(u32(Mnem::count()));
  for (size_t i = 0; i < Mnem::count(); ++i) w.str(Mnem::from_id(u16(i)).str());
  // the functions kept, their mnemonics numbered as this run numbers them, then the new ones
  for (auto& rec : index_) {
    BinReader r(file_->view(), rec.at);
    size_t before = w.out.size();
    if (!copy_record(r, w, mnems_)) w.out.resize(before);  // not kept (find does not read it either)
  }
  std::vector<u16> same(Mnem::count());
  for (size_t i = 0; i < same.size(); ++i) same[i] = u16(i);
  for (BinReader r(added_.out, 0); r.ok() && !r.done();)
    if (!copy_record(r, w, same)) break;
  file_.reset();  // the file is replaced (not while it is mapped)
  index_.clear();
  write_cache_file(path_, w.out);
  added_.out.clear();
}

namespace {

// The rebuilt store's file: its header; the mnemonics as in the original's; then each function: its key (the name's
// hash and the size), the kept head (below), its instructions, fields and the shape's indexed displacements, then its
// name and bytes.
constexpr std::string_view REBUILT_MAGIC = "verifier-rebuilt-code 1\n";

u64 rebuilt_key(std::string_view name, u64 size) { return u64(std::hash<std::string_view>()(name)) * 31 + size; }

// a kept function as read: the parts of Code it gives
struct Kept {
  u64 key = 0;
  i64 cut = 0, reach = 0;
  u8 ends_in_jump = 0;
  u32 ninsns = 0, nfields = 0, nindexed = 0;
  std::vector<Lean> insns;
  std::vector<Field> fields;
  std::vector<i64> indexed;
  std::string name, code;
};

void put_kept(BinWriter& w, const Kept& k) {
  w.put(k.key);
  w.put(k.cut);
  w.put(k.reach);
  w.put(k.ends_in_jump);
  w.put(u32(k.insns.size()));
  w.put(u32(k.fields.size()));
  w.put(u32(k.indexed.size()));
  w.array(k.insns.data(), k.insns.size());
  w.array(k.fields.data(), k.fields.size());
  w.array(k.indexed.data(), k.indexed.size());
  w.str(k.name);
  w.str(k.code);
}

// false: a damaged record, or a mnemonic the table does not have
bool get_kept(BinReader& r, Kept& k, const std::vector<u16>& mnems) {
  r.get(k.key);
  r.get(k.cut);
  r.get(k.reach);
  r.get(k.ends_in_jump);
  r.get(k.ninsns);
  r.get(k.nfields);
  r.get(k.nindexed);
  auto array = [&](auto& v, u32 n) {
    std::string_view b = r.take(size_t(n) * sizeof(v[0]));
    if (!r.ok()) return;
    v.resize(n);
    if (n) std::memcpy(v.data(), b.data(), b.size());
  };
  array(k.insns, k.ninsns);
  array(k.fields, k.nfields);
  array(k.indexed, k.nindexed);
  r.str(k.name);
  r.str(k.code);
  if (!r.ok()) return false;
  for (Lean& l : k.insns) {
    if (l.mnem >= mnems.size()) return false;
    l.mnem = mnems[l.mnem];
  }
  return true;
}

}  // namespace

RebuiltStore::RebuiltStore(std::string path, std::string key) : path_(std::move(path)), key_(std::move(key)) {
  if (path_.empty()) return;
  std::string head = cache_header(REBUILT_MAGIC, key_);
  file_ = open_cache_file(path_, head);
  if (!file_) return;
  BinReader r(file_->view(), head.size());
  u32 n = 0;
  r.get(n);
  for (u32 i = 0; r.ok() && i < n; ++i) {
    std::string s;
    if (r.str(s)) mnems_.push_back(Mnem(s).id());
  }
  while (r.ok() && !r.done()) {  // each record's key, the rest skipped
    size_t at = r.at();
    Kept k;
    r.get(k.key);
    r.get(k.cut);
    r.get(k.reach);
    r.get(k.ends_in_jump);
    r.get(k.ninsns);
    r.get(k.nfields);
    r.get(k.nindexed);
    r.take(size_t(k.ninsns) * sizeof(Lean) + size_t(k.nfields) * sizeof(Field) + size_t(k.nindexed) * sizeof(i64));
    for (int s = 0; s < 2; ++s) {  // the name and the bytes
      u32 len = 0;
      r.get(len);
      r.take(len);
    }
    index_.push_back({k.key, at});
  }
  if (!r.ok()) {  // a damaged file is not used
    index_.clear();
    file_.reset();
    return;
  }
  std::sort(index_.begin(), index_.end());
  used_.assign(index_.size(), false);
}

std::shared_ptr<const Code> RebuiltStore::find(const Image& img, u64 start, u64 end, std::string_view name) {
  if (!file_ || name.empty()) return ++missed, nullptr;
  u64 key = rebuilt_key(name, end - start);
  for (auto it = std::lower_bound(index_.begin(), index_.end(), Record{key, 0}); it != index_.end() && it->key == key;
       ++it) {
    BinReader r(file_->view(), it->at);
    Kept k;
    if (!get_kept(r, k, mnems_) || k.name != name) continue;
    // the kept function, with its own bytes, at this place
    Code kept(img, start, end, Code::Undecoded{});
    kept.code = k.code;
    kept.insns = k.insns;
    kept.field_list = k.fields;
    kept.cut = k.cut;
    kept.complete = true;
    kept.shape = {true, k.ends_in_jump != 0, k.reach, k.indexed};
    auto fields = same_code_fields(kept, img, start, end, false);
    if (!fields || kept.code.size() > size_t(end - start)) continue;
    std::shared_ptr<Code> c(new Code(img, start, end, Code::Undecoded{}));
    c->code = c->code.substr(0, k.code.size());
    c->lean_ = std::move(k.insns);
    c->fields_ = std::move(*fields);
    c->insns = c->lean_;
    c->field_list = c->fields_;
    c->cut = k.cut;
    c->complete = true;
    c->shape = std::move(kept.shape);
    if (check_fast_path()) {
      Code full(img, start, end);
      auto same_lean = [](const Lean& a, const Lean& b) {
        return a.off == b.off && a.field == b.field && a.mnem == b.mnem && a.size == b.size && a.nfields == b.nfields &&
               a.addressed == b.addressed;
      };
      auto same_field = [](const Field& a, const Field& b) {
        return a.value == b.value && a.access == b.access && a.indexed == b.indexed && a.off == b.off &&
               a.size == b.size && a.kind == b.kind;
      };
      bool same = full.code == c->code && full.cut == c->cut && full.complete && !full.resume && full.tables.empty() &&
                  full.relocated == c->relocated && full.shape.known &&
                  full.shape.ends_in_jump == c->shape.ends_in_jump && full.shape.reach == c->shape.reach &&
                  full.shape.indexed == c->shape.indexed &&
                  std::equal(full.insns.begin(), full.insns.end(), c->insns.begin(), c->insns.end(), same_lean) &&
                  std::equal(full.field_list.begin(), full.field_list.end(), c->field_list.begin(), c->field_list.end(),
                             same_field);
      if (!same) throw std::logic_error("rebuilt store: a kept function differs from a decode at " + hex(start));
    }
    if (!used_[size_t(it - index_.begin())]) {
      used_[size_t(it - index_.begin())] = true;
      Kept again = std::move(k);
      again.insns.assign(c->insns.begin(), c->insns.end());  // numbered as this run numbers them
      put_kept(kept_, again);
    }
    ++found;
    return c;
  }
  ++missed;
  return nullptr;
}

void RebuiltStore::add(const Code& c, std::string_view name) {
  if (path_.empty() || name.empty() || !c.shape.known || c.resume || !c.tables.empty()) return;
  if (!added_.insert({c.start, c.end}).second) return;
  Kept k;
  k.key = rebuilt_key(name, c.end - c.start);
  k.cut = c.cut;
  k.reach = c.shape.reach;
  k.ends_in_jump = c.shape.ends_in_jump;
  k.insns.assign(c.insns.begin(), c.insns.end());
  k.fields.assign(c.field_list.begin(), c.field_list.end());
  k.indexed = c.shape.indexed;
  k.name = name;
  k.code = c.code;
  put_kept(kept_, k);
}

void RebuiltStore::save() {
  if (path_.empty() || (added_.empty() && std::find(used_.begin(), used_.end(), false) == used_.end())) return;
  BinWriter w;
  w.out = cache_header(REBUILT_MAGIC, key_);
  w.put(u32(Mnem::count()));
  for (size_t i = 0; i < Mnem::count(); ++i) w.str(Mnem::from_id(u16(i)).str());
  w.out += kept_.out;
  file_.reset();
  index_.clear();
  write_cache_file(path_, w.out);
}

std::shared_ptr<const Code> CodeCache::code(u64 start, u64 end) {
  auto it = live_.find({start, end});
  if (it != live_.end()) return it->second;
  std::shared_ptr<const Code> c;
  std::string_view name;
  if (store_) {
    c = store_->find(*img_, start, end);
  } else if (rebuilt_store_) {
    name = name_of_(start);
    c = rebuilt_store_->find(*img_, start, end, name);
  }
  if (!c) {
    c = std::make_shared<const Code>(*img_, start, end);
    if (store_) store_->add(*c);
    if (rebuilt_store_) rebuilt_store_->add(*c, name);
  }
  return live_.emplace(std::make_pair(start, end), std::move(c)).first->second;
}

}  // namespace verifier
