#include "code_store.hpp"

#include <algorithm>
#include <cstring>

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

std::shared_ptr<const Code> CodeCache::code(u64 start, u64 end) {
  auto it = live_.find({start, end});
  if (it != live_.end()) return it->second;
  std::shared_ptr<const Code> c = store_ ? store_->find(*img_, start, end) : nullptr;
  if (!c) {
    c = std::make_shared<const Code>(*img_, start, end);
    if (store_) store_->add(*c);
  }
  return live_.emplace(std::make_pair(start, end), std::move(c)).first->second;
}

}  // namespace verifier
