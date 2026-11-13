#include "name_cache.hpp"

#include <algorithm>
#include <cstring>
#include <unordered_map>
#include <unordered_set>

#include "cache_file.hpp"
#include "demangle.hpp"
#include "names.hpp"

namespace verifier {

// --- the name cache -----------------------------------------------------------------------------------------
// A binary file, used in place (little-endian u32s):
//   "verifier-names 4\n" key "\n", zero-padded to a multiple of 8
//   nstrings, nentries, entry_slots, string_slots     (slots: powers of two)
//   string_end[nstrings]       string i is text[string_end[i-1], string_end[i])
//   entries[nentries][7]       decorated, flags (1: not demangled), qualified, signature, owner, and the qualified
//                              name's last one and two components (string ids), in the map's order
//   entry_index[entry_slots]   entry + 1 at name_hash(decorated), linear probing (0: empty)
//   string_index[string_slots] string id + 1 at name_hash(string)
//   text
// Every string is stored once, so equal strings have equal ids: the name tables compare ids. The entries are in
// the order the build's map had them, so the next build's names are found by reading on (the index for the rest).
// The text has the strings a run reads together: the newest build's first, the other builds' after them.

namespace {

constexpr const char* NAMES_MAGIC = "verifier-names 4\n";

constexpr size_t ROW = 7;  // u32s per entry

constexpr size_t CHUNK = size_t(1) << 20;  // the text of strings added in a run, in chunks of at least this

u32 slots_for(size_t n) {
  u32 c = 16;
  while (c < 2 * n) c *= 2;
  return c;
}

// the file's header: magic and key, zero-padded to a multiple of 8
std::string file_head(const std::string& key) {
  std::string h = cache_header(NAMES_MAGIC, key);
  h.resize((h.size() + 7) / 8 * 8, '\0');
  return h;
}

// linear probing in an index of `slots` (a power of two) from hash h for the value + 1 that `hit` accepts: the value,
// or -1
template <class Hit>
long probe(const u32* index, u32 slots, u32 h, Hit hit) {
  if (!slots) return -1;
  for (u32 i = h & (slots - 1);; i = (i + 1) & (slots - 1)) {
    u32 v = index[i];
    if (!v) return -1;
    if (hit(v - 1)) return long(v - 1);
  }
}

// an index of `slots` holding k + 1 at keys[k]'s hash
std::vector<u32> build_index(const std::vector<std::string_view>& keys, u32 slots) {
  std::vector<u32> idx(slots);
  for (size_t k = 0; k < keys.size(); ++k) {
    u32 i = u32(name_hash(keys[k])) & (slots - 1);
    while (idx[i]) i = (i + 1) & (slots - 1);
    idx[i] = u32(k + 1);
  }
  return idx;
}

}  // namespace

NameCache::NameCache(std::string path, std::string key) : path_(std::move(path)), key_(std::move(key)) {
  if (path_.empty()) return;
  map_ = open_cache_file(path_, cache_header(NAMES_MAGIC, key_));
  if (!map_) return;
  auto drop = [&] {
    file_ = {};
    map_.reset();
  };  // the counts stay 0: nothing reads the file
  try {
    file_ = map_->view();
    size_t at = file_head(key_).size();  // the header, padded to 8
    if (file_.size() < at + 16 || file_.compare(0, at, file_head(key_)) != 0) {
      drop();
      return;
    }
    const u32* h = reinterpret_cast<const u32*>(file_.data() + at);
    u64 ns = h[0], ne = h[1], es = h[2], ss = h[3];
    u64 words = 4 + ns + ROW * ne + es + ss;
    if ((es & (es - 1)) || (ss & (ss - 1)) || !es || !ss || file_.size() < at + 4 * words) {
      drop();
      return;
    }
    str_end_ = h + 4;
    ent_ = str_end_ + ns;
    eidx_ = ent_ + ROW * ne;
    sidx_ = eidx_ + es;
    text_ = file_.data() + at + 4 * words;
    u64 text_size = file_.size() - at - 4 * words;
    if (ns && str_end_[ns - 1] != text_size) {
      drop();
      return;
    }
    for (u64 i = 0; i < ns; ++i)
      if (str_end_[i] > text_size || (i && str_end_[i] < str_end_[i - 1])) {
        drop();
        return;
      }
    for (u64 i = 0; i < ROW * ne; ++i)
      if ((i % ROW == 1 ? ent_[i] > 1 : ent_[i] >= ns)) {
        drop();
        return;
      }
    for (u64 i = 0; i < es; ++i)
      if (eidx_[i] > ne) {
        drop();
        return;
      }
    for (u64 i = 0; i < ss; ++i)
      if (sidx_[i] > ns) {
        drop();
        return;
      }
    nstr_ = u32(ns);
    nent_ = u32(ne);
    eslots_ = u32(es);
    sslots_ = u32(ss);
    loaded_from_file_ = true;
  } catch (...) { drop(); }
}

NameCache::~NameCache() = default;

std::string_view NameCache::text(u32 id) const {
  if (id < nstr_) {
    u32 b = id ? str_end_[id - 1] : 0;
    return std::string_view(text_ + b, str_end_[id] - b);
  }
  return new_text_[id - nstr_];
}

long NameCache::find_new(std::string_view s, u32 h) const {
  if (new_index_.empty()) return -1;
  size_t mask = new_index_.size() - 1;
  for (size_t i = h & mask;; i = (i + 1) & mask) {
    u64 e = new_index_[i];
    if (!e) return -1;
    u32 v = u32(e);
    if (u32(e >> 32) == h && new_text_[v - 1] == s) return long(nstr_ + v - 1);
  }
}

std::optional<u32> NameCache::id_of(std::string_view s) const {
  u32 h = u32(name_hash(s));
  if (long k = probe(sidx_, sslots_, h, [&](u32 id) { return text(id) == s; }); k >= 0) return u32(k);
  if (long k = find_new(s, h); k >= 0) return u32(k);
  return std::nullopt;
}

void NameCache::reserve(size_t strings) {
  new_text_.reserve(strings);
  size_t slots = std::max<size_t>(1024, new_index_.size());
  while (slots < 2 * strings) slots *= 2;
  if (slots == new_index_.size()) return;
  std::vector<u64> idx(slots);
  size_t mask = slots - 1;
  for (u64 e : new_index_)
    if (e) {
      size_t i = size_t(e >> 32) & mask;
      while (idx[i]) i = (i + 1) & mask;
      idx[i] = e;
    }
  new_index_ = std::move(idx);
}

u32 NameCache::intern(std::string_view s) {
  u32 h = u32(name_hash(s));
  if (long k = probe(sidx_, sslots_, h, [&](u32 id) { return text(id) == s; }); k >= 0) return u32(k);
  if (long k = find_new(s, h); k >= 0) return u32(k);
  if (2 * (new_text_.size() + 1) > new_index_.size()) reserve(new_text_.size() + 1);  // at most half full
  if (s.size() > chunk_left_) {
    size_t n = std::max(CHUNK, s.size());
    chunks_.push_back(std::make_unique<char[]>(n));
    chunk_at_ = chunks_.back().get();
    chunk_left_ = n;
  }
  if (!s.empty()) std::memcpy(chunk_at_, s.data(), s.size());
  std::string_view v(chunk_at_, s.size());
  chunk_at_ += s.size();
  chunk_left_ -= s.size();
  new_text_.push_back(v);
  size_t mask = new_index_.size() - 1, i = h & mask;
  while (new_index_[i]) i = (i + 1) & mask;
  new_index_[i] = u64(h) << 32 | new_text_.size();
  return nstr_ + u32(new_text_.size() - 1);
}

long NameCache::find_entry(std::string_view d) const {
  return probe(eidx_, eslots_, u32(name_hash(d)), [&](u32 k) { return text(ent_[ROW * size_t(k)]) == d; });
}

NameIds NameCache::file_entry(u32 k) const {
  const u32* e = ent_ + ROW * size_t(k);
  return NameIds{e[0], e[2], e[3], e[4], e[5], e[6], e[1] != 0};
}

NameInfo NameCache::info(const NameIds& n) const {
  return NameInfo{text(n.decorated), text(n.qualified), text(n.signature), text(n.owner)};
}

std::optional<NameIds> NameCache::find(std::string_view d) const {
  long k = find_entry(d);
  if (k >= 0) return file_entry(u32(k));
  if (auto id = id_of(d); id && *id < new_entry_of_.size() && new_entry_of_[*id])
    return new_entries_[new_entry_of_[*id] - 1];
  return std::nullopt;
}

std::vector<NameIds> NameCache::load(const std::vector<std::string_view>& decorated) {
  std::vector<NameIds> infos(decorated.size());
  std::unique_ptr<Demangler> dm;  // made at the first name the file lacks
  std::optional<u32> empty;       // the empty string's id
  auto empty_id = [&] {
    if (!empty) empty = intern({});
    return *empty;
  };
  failed_.clear();
  u32 next = 0;  // the file entry after the last one found: usually the next name's
  for (size_t i = 0; i < decorated.size(); ++i) {
    std::string_view d = decorated[i];
    long k = next < nent_ && text(ent_[ROW * size_t(next)]) == d ? long(next) : find_entry(d);
    if (k >= 0) {
      infos[i] = file_entry(u32(k));
      next = u32(k) + 1;
      if (infos[i].failed) failed_.push_back(text(infos[i].decorated));
      continue;
    }
    if (!dm) {  // the first name the file lacks: room for the rest (about two new strings each)
      dm = std::make_unique<Demangler>();
      reserve(new_text_.size() + 2 * (decorated.size() - i));
      new_entries_.reserve(new_entries_.size() + decorated.size() - i);
    }
    u32 dec = intern(d);
    if (new_entry_of_.size() <= dec) new_entry_of_.resize(std::max<size_t>(dec + 1, 2 * new_entry_of_.size()));
    if (u32 e = new_entry_of_[dec]) {  // given twice
      infos[i] = new_entries_[e - 1];
      continue;
    }
    NameKeys keys;
    NameIds ni;
    ni.decorated = dec;
    ni.failed = !dm->keys(d, keys);
    // most keys are the name, or the qualified name, or a part of it: those take its id without a lookup
    std::string_view q = keys.qualified, l1 = last_components(q, 1), l2 = last_components(q, 2);
    ni.qualified = q == d ? dec : intern(q);
    ni.signature = keys.signature.empty() ? empty_id() : intern(keys.signature);
    ni.owner = keys.owner == q ? ni.qualified : intern(keys.owner);
    ni.last2 = l2.size() == q.size() ? ni.qualified : intern(l2);
    ni.last1 = l1.size() == l2.size() ? ni.last2 : intern(l1);
    if (ni.failed) failed_.push_back(text(dec));
    new_entries_.push_back(ni);
    new_entry_of_[dec] = u32(new_entries_.size());
    infos[i] = ni;
  }
  if (!failed_.empty()) {  // each once
    std::unordered_set<std::string_view, SvHash> seen;
    failed_.erase(
        std::remove_if(failed_.begin(), failed_.end(), [&](std::string_view s) { return !seen.insert(s).second; }),
        failed_.end());
  }
  used_.clear();
  used_.reserve(infos.size());
  for (auto& n : infos) used_.push_back(text(n.decorated));
  return infos;
}

void NameCache::save(bool force) {
  if (path_.empty()) return;
  if (!force && loaded_from_file_ && new_entries_.size() < SAVE_THRESHOLD) return;
  std::vector<std::string_view> names;  // in map order, each once
  std::unordered_set<std::string_view, SvHash> seen;
  seen.reserve(2 * used_.size());
  for (auto n : used_)
    if (seen.insert(n).second) names.push_back(n);
  size_t current = names.size();
  bool in_order = loaded_from_file_ && new_entries_.empty() && current <= nent_ && nent_ - current <= current;
  for (size_t k = 0; in_order && k < current; ++k) in_order = text(ent_[ROW * k]) == names[k];
  if (in_order) return;  // the file starts with these, in this order, and keeps no more others than allowed
  // then the file's names of other builds, the most recently saved first
  for (u32 k = 0; k < nent_ && names.size() < 2 * current; ++k)
    if (std::string_view d = text(ent_[ROW * size_t(k)]); seen.insert(d).second) names.push_back(d);
  // the strings of these names, each once
  std::vector<std::string_view> strs;
  std::unordered_map<std::string_view, u32, SvHash> ids;
  ids.reserve(4 * names.size());
  auto id = [&](u32 from) {
    std::string_view s = text(from);
    auto [it, fresh] = ids.emplace(s, u32(strs.size()));
    if (fresh) strs.push_back(s);
    return it->second;
  };
  // the strings numbered in the order the text keeps them: this build's, then the rest
  std::vector<u32> ent;
  ent.reserve(ROW * names.size());
  for (auto& n : names) {
    NameIds ni = *find(n);
    for (u32 v : {id(ni.decorated), u32(ni.failed), id(ni.qualified), id(ni.signature), id(ni.owner), id(ni.last1),
                  id(ni.last2)})
      ent.push_back(v);
  }
  u32 es = slots_for(names.size()), ss = slots_for(strs.size());
  std::vector<u32> ends;
  ends.reserve(strs.size());
  u64 total = 0;
  for (auto s : strs) {
    total += s.size();
    if (total > 0xffffffffu) return;  // too large for the format: no cache
    ends.push_back(u32(total));
  }
  std::string out = file_head(key_);
  out.reserve(out.size() + 4 * (4 + ends.size() + ent.size() + es + ss) + total);
  auto put = [&](const std::vector<u32>& v) { out.append(reinterpret_cast<const char*>(v.data()), 4 * v.size()); };
  put({u32(strs.size()), u32(names.size()), es, ss});
  put(ends);
  put(ent);
  put(build_index(names, es));
  put(build_index(strs, ss));
  for (auto& s : strs) out += s;
  write_cache_file(path_, out);  // replaces the file whole: runs that have the old one mapped keep reading it
}

}  // namespace verifier
