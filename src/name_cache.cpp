#include "name_cache.hpp"

#include <algorithm>
#include <cstring>
#include <unordered_set>

#include "cache_file.hpp"
#include "names.hpp"
#include "undname.hpp"

namespace verifier {

// --- the name cache -----------------------------------------------------------------------------------------
// A binary file, used in place (little-endian u32s):
//   "verifier-names 3\n" key "\n", zero-padded to a multiple of 8
//   nstrings, nentries, entry_slots, string_slots     (slots: powers of two)
//   string_end[nstrings]       string i is text[string_end[i-1], string_end[i])
//   entries[nentries][8]       decorated, has_und, und, qualified, signature, owner, and the qualified name's last
//                              one and two components (string ids; has_und 0/1), in the map's order
//   entry_index[entry_slots]   entry + 1 at name_hash(decorated), linear probing (0: empty)
//   string_index[string_slots] string id + 1 at name_hash(string)
//   text
// Every string is stored once, so equal strings have equal ids: the name tables compare ids. The entries are in
// the order the build's map had them, so the next build's names are found by reading on (the index for the rest).
// The text has the strings a run reads together: the newest build's first, its undecorated names (shown only on
// request) after them, and the other builds' last.

namespace {

constexpr const char* NAMES_MAGIC = "verifier-names 3\n";

constexpr size_t ROW = 8;  // u32s per entry

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

// linear probing in an index of `slots` (a power of two) for the value + 1 that `hit` accepts: the value, or -1
template <class Hit>
long probe(const u32* index, u32 slots, std::string_view s, Hit hit) {
  if (!slots) return -1;
  for (u32 i = u32(name_hash(s)) & (slots - 1);; i = (i + 1) & (slots - 1)) {
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

NameCache::NameCache(std::string path, std::string key, std::string undname)
    : path_(std::move(path)), key_(std::move(key)), undname_(std::move(undname)) {
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

std::string_view NameCache::text(u32 id) const {
  if (id < nstr_) {
    u32 b = id ? str_end_[id - 1] : 0;
    return std::string_view(text_ + b, str_end_[id] - b);
  }
  return new_text_[id - nstr_];
}

std::optional<u32> NameCache::id_of(std::string_view s) const {
  if (long k = probe(sidx_, sslots_, s, [&](u32 id) { return text(id) == s; }); k >= 0) return u32(k);
  auto it = new_ids_.find(s);
  if (it != new_ids_.end()) return it->second;
  return std::nullopt;
}

u32 NameCache::intern(std::string s) {
  if (auto id = id_of(s)) return *id;
  u32 id = nstr_ + u32(new_text_.size());
  std::string_view v = owned_.emplace_back(std::move(s));
  new_text_.push_back(v);
  new_ids_.emplace(v, id);
  return id;
}

long NameCache::find_entry(std::string_view d) const {
  return probe(eidx_, eslots_, d, [&](u32 k) { return text(ent_[ROW * size_t(k)]) == d; });
}

NameIds NameCache::file_entry(u32 k) const {
  const u32* e = ent_ + ROW * size_t(k);
  return NameIds{e[0], e[2], e[3], e[4], e[5], e[6], e[7], e[1] != 0};
}

NameInfo NameCache::info(const NameIds& n) const {
  return NameInfo{n.has_und, text(n.decorated), text(n.und), text(n.qualified), text(n.signature), text(n.owner)};
}

std::optional<NameIds> NameCache::find(std::string_view d) const {
  long k = find_entry(d);
  if (k >= 0) return file_entry(u32(k));
  auto it = new_entries_.find(d);
  if (it == new_entries_.end()) return std::nullopt;
  return it->second;
}

std::vector<NameIds> NameCache::load(const std::vector<std::string_view>& decorated) {
  std::vector<NameIds> infos(decorated.size());
  std::vector<char> found(decorated.size());
  std::vector<std::string> missing;
  u32 next = 0;  // the file entry after the last one found: usually the next name's
  for (size_t i = 0; i < decorated.size(); ++i) {
    long k = next < nent_ && text(ent_[ROW * size_t(next)]) == decorated[i] ? long(next) : find_entry(decorated[i]);
    if (k < 0) {
      missing.emplace_back(decorated[i]);
      continue;
    }
    infos[i] = file_entry(u32(k));
    found[i] = 1;
    next = u32(k) + 1;
  }
  if (!missing.empty()) {
    std::sort(missing.begin(), missing.end());
    missing.erase(std::unique(missing.begin(), missing.end()), missing.end());
    auto und = undecorate(missing, undname_);
    for (auto& d : missing) {
      auto it = und.find(d);
      const std::string& u = it == und.end() ? d : it->second;
      std::string q = qualified(u);
      u32 l1 = intern(std::string(last_components(q, 1))), l2 = intern(std::string(last_components(q, 2)));
      u32 dec = intern(d), un = intern(it == und.end() ? "" : it->second), qi = intern(std::move(q)),
          sg = intern(signature(u)), ow = intern(static_owner(u));
      new_entries_.emplace(text(dec), NameIds{dec, un, qi, sg, ow, l1, l2, it != und.end()});
    }
    for (size_t i = 0; i < decorated.size(); ++i)
      if (!found[i]) infos[i] = *find(decorated[i]);
  }
  used_.clear();
  used_.reserve(infos.size());
  for (auto& n : infos) used_.push_back(text(n.decorated));
  return infos;
}

void NameCache::save() {
  if (path_.empty()) return;
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
  auto id = [&](std::string_view s) {
    auto [it, fresh] = ids.emplace(s, u32(strs.size()));
    if (fresh) strs.push_back(s);
    return it->second;
  };
  // the ids, in the order the text keeps them
  std::vector<NameIds> infos;
  infos.reserve(names.size());
  for (auto& n : names) infos.push_back(*find(n));
  for (size_t k = 0; k < current; ++k)
    for (u32 v :
         {infos[k].decorated, infos[k].qualified, infos[k].signature, infos[k].owner, infos[k].last1, infos[k].last2})
      id(text(v));
  for (size_t k = 0; k < current; ++k) id(text(infos[k].und));
  std::vector<u32> ent;
  ent.reserve(ROW * names.size());
  for (auto& ni : infos)
    for (u32 v : {id(text(ni.decorated)), u32(ni.has_und), id(text(ni.und)), id(text(ni.qualified)),
                  id(text(ni.signature)), id(text(ni.owner)), id(text(ni.last1)), id(text(ni.last2))})
      ent.push_back(v);
  u32 es = slots_for(names.size()), ss = slots_for(strs.size());
  std::vector<u32> ends;
  u64 total = 0;
  for (auto s : strs) {
    total += s.size();
    if (total > 0xffffffffu) return;  // too large for the format: no cache
    ends.push_back(u32(total));
  }
  std::string out = file_head(key_);
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
