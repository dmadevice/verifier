#include "inputs.hpp"

#include "cache_file.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <stdexcept>

#include "json.hpp"
#include "sha256.hpp"

namespace verifier {

namespace {

// a decimal JSON member value at line[i], ended by ',' or '}': its value, and where it ends
bool member_int(std::string_view line, size_t i, u64& v, size_t& end) {
  return parse_dec(line, i, v, end) && end < line.size() && (line[end] == ',' || line[end] == '}');
}

// `{"ea": <int>` at the start of a JSON line (IDA's exports write "ea" first): its value, and where it ends
bool lead_ea(std::string_view line, u64& ea, size_t& end) {
  static constexpr std::string_view head = "{\"ea\": ";
  return line.substr(0, head.size()) == head && member_int(line, head.size(), ea, end);
}

// The snapshot: its header (format and key), the string table (u64 length, then the text), then the fields as u64s,
// a string as (offset, length) in the table, which holds each distinct string once; then the image's headers
// (u64 length, then the bytes), where the laid-out image starts (page-aligned) and its size, and the image. Only the
// table and the image are used in place once read.
constexpr std::string_view SNAPSHOT_MAGIC = "verifier-snapshot 5\n";

struct StringTable {
  std::string text;
  std::unordered_map<std::string, u64> at;  // string -> offset in `text`
  void put(BinWriter& w, std::string_view s) {
    auto [it, fresh] = at.try_emplace(std::string(s), text.size());
    if (fresh) text += s;
    w.put(it->second);
    w.put(u64(s.size()));
  }
};

}  // namespace

// -- tables ------------------------------------------------------------------------------------------------

namespace {
bool ea_below(const IdaFunction& f, u64 ea) { return f.ea < ea; }
}  // namespace

const IdaFunction* FunctionTable::find(u64 ea) const {
  auto it = std::lower_bound(fs_.begin(), fs_.end(), ea, ea_below);
  return it != fs_.end() && it->ea == ea ? &*it : nullptr;
}

const IdaFunction& FunctionTable::at(u64 ea) const {
  if (const IdaFunction* f = find(ea)) return *f;
  throw std::out_of_range("no function at " + hex(ea));
}

void FunctionTable::set(const IdaFunction& f) {
  auto it = std::lower_bound(fs_.begin(), fs_.end(), f.ea, ea_below);
  if (it != fs_.end() && it->ea == f.ea)
    *it = f;
  else
    fs_.insert(it, f);
}

void FunctionTable::assign(std::vector<IdaFunction> fs) {
  // already in order, one at each address (the snapshot's): kept as is
  if (std::adjacent_find(fs.begin(), fs.end(), [](auto& a, auto& b) { return a.ea >= b.ea; }) == fs.end()) {
    fs_ = std::move(fs);
    fs_.shrink_to_fit();
    return;
  }
  std::stable_sort(fs.begin(), fs.end(), [](const IdaFunction& a, const IdaFunction& b) { return a.ea < b.ea; });
  fs_.clear();
  for (auto& f : fs) {
    if (!fs_.empty() && fs_.back().ea == f.ea)
      fs_.back() = f;  // the later one
    else
      fs_.push_back(f);
  }
  fs_.shrink_to_fit();
}

Symbols::Symbols(const std::vector<std::pair<u64, std::string_view>>& syms) {
  // the symbols by address (map order within one), then the addresses in the order of their first symbol
  std::vector<u32> by_addr(syms.size());
  for (u32 i = 0; i < by_addr.size(); ++i) by_addr[i] = i;
  std::stable_sort(by_addr.begin(), by_addr.end(), [&](u32 a, u32 b) { return syms[a].first < syms[b].first; });
  std::vector<std::pair<u32, u64>> first_seen;  // (first symbol, address)
  names_.reserve(syms.size());
  for (u32 i : by_addr) {
    u64 va = syms[i].first;
    if (vas_.empty() || vas_.back() != va) {
      vas_.push_back(va);
      first_.push_back(u32(names_.size()));
      first_seen.emplace_back(i, va);
    }
    names_.push_back(syms[i].second);
  }
  first_.push_back(u32(names_.size()));
  std::sort(first_seen.begin(), first_seen.end());
  for (auto& [i, va] : first_seen) order_.push_back(va);
}

long Symbols::index(u64 va) const {
  auto it = std::lower_bound(vas_.begin(), vas_.end(), va);
  return it != vas_.end() && *it == va ? long(it - vas_.begin()) : -1;
}

std::span<const std::string_view> Symbols::names(u64 va) const {
  long i = index(va);
  if (i < 0) return {};
  return {names_.data() + first_[size_t(i)], names_.data() + first_[size_t(i) + 1]};
}

// -- Original ------------------------------------------------------------------------------------------------

Original::Original(const Config& p, const std::function<std::string(const std::string&)>& hash_file) : config_(&p) {
  if (!file_exists(p.original)) {
    std::fprintf(stderr, "verifier: no original binary %s\n", p.original.c_str());
    std::exit(2);
  }
  digest = p.original_sha256;
  // the image laid out and the tables from the text exports, which rarely change: a snapshot in the cache, mapped. A
  // run from the snapshot does not read the original, so the original is checked when the snapshot is made (its key
  // holds the configured hash)
  std::string key = cache_key_ = snapshot_key(p);
  std::string snapshot = key.empty() ? std::string() : p.cache_file("original-snapshot.bin");
  if (!snapshot.empty() && load_snapshot(snapshot, key)) return;
  if (!digest.empty() && hash_file(p.original) != digest) {
    std::fprintf(stderr, "original image hash mismatch: %s is not %s\n", p.original.c_str(), digest.c_str());
    std::exit(1);
  }
  img = Image::load(p.original);
  load_exports();
  if (!snapshot.empty()) save_snapshot(snapshot, key);
}

void Original::load_exports() {
  const Config& p = *config_;
  std::vector<IdaFunction> fs;  // in the file's order
  for_each_file_line(p.functions, [&](std::string_view line) {
    if (strip(line).empty()) return;
    auto v = json::parse(line);
    IdaFunction f;
    f.ea = u64(v["ea"].as_int());
    f.size = u64(v["size"].as_int());
    f.name = keep(v["name"].as_str());
    f.lib = v["lib"].as_bool();
    f.thunk = v["thunk"].as_bool();
    fs.push_back(f);
  });
  functions.assign(fs);
  {
    // by name, in the order the file first has each address
    std::unordered_set<u64> seen;
    for (auto& f : fs)
      if (seen.insert(f.ea).second) by_name.set(functions.at(f.ea).name, f.ea);
  }
  std::vector<json::Value> matches;
  if (file_exists(p.library_matches)) matches = json::parse(read_file(p.library_matches))["matches"].arr;
  if (file_exists(p.vtables)) {
    for (auto& line : read_lines(p.vtables)) {
      if (strip(line).empty()) continue;
      auto v = json::parse(line);
      u64 ea = u64(v["vtable_ea"].as_int());
      by_name.set(keep(v["name"].as_str()), ea);
      std::vector<u64> slots;
      for (auto& s : v["slots"].arr) slots.push_back(u64(s.as_int()));
      vtables[ea] = slots;
    }
  }
  // library symbols matched at exactly one original address, and no other symbol there; IDA names win
  std::unordered_map<std::string, std::set<u64>> s2e;
  std::unordered_map<u64, std::set<std::string>> e2s;
  for (auto& m : matches) {
    s2e[m["symbol"].as_str()].insert(u64(m["ea"].as_int()));
    e2s[u64(m["ea"].as_int())].insert(m["symbol"].as_str());
  }
  for (auto& [sym, eas] : s2e) {
    if (eas.size() != 1) continue;
    u64 ea = *eas.begin();
    const u64* at = by_name.find(sym);
    if (e2s[ea].size() == 1 && (!at || *at == ea)) by_name.set(keep(sym), ea);
  }
  if (file_exists(p.symbols)) {
    for (auto& line : read_lines(p.symbols)) {
      if (strip(line).empty() || starts_with(line, "#")) continue;
      auto w = split_ws(line);
      by_name.set(keep(w[0]), parse_hex(w[1]));
    }
  }
  by_name.set("__ImageBase", img.base);
  for (auto& m : matches) {
    u64 ea = u64(m["ea"].as_int());
    if (!functions.contains(ea)) continue;
    linked[ea] = Linked{m["lib"].as_str(), m["symbol"].as_str(), true};
  }
  if (file_exists(p.library_functions)) {
    auto doc = json::parse(read_file(p.library_functions));
    for (auto& m : doc.arr) {
      u64 ea = u64(m["ea"].as_int());
      linked[ea] = Linked{m["lib"].as_str(), "", false};
    }
  }
  load_items();
}

std::string Original::snapshot_key(const Config& p) {
  std::string key = "verifier original snapshot 4\n" + p.original_sha256 + "\n";
  i64 recent = two_seconds_ago();
  for (auto* f : p.snapshot_inputs()) {
    i64 time = std::numeric_limits<i64>::min();
    key += file_stamp(*f, &time) + "\n";
    if (time >= recent) return "";
  }
  return key;
}

void Original::save_snapshot(const std::string& path, const std::string& key) const {
  BinWriter w;
  StringTable st;
  auto u = [&](u64 v) { w.put(v); };
  u(functions.size());
  for (const IdaFunction& f : functions) {
    u(f.ea);
    u(f.size);
    st.put(w, f.name);
    u(u64(f.lib) | u64(f.thunk) << 1);
  }
  u(vtables.size());
  for (auto& [ea, slots] : vtables) {
    u(ea);
    u(slots.size());
    for (u64 s : slots) u(s);
  }
  u(by_name.size());
  for (auto& [name, va] : by_name) {
    st.put(w, name);
    u(va);
  }
  const std::vector<u32>& index = by_name.index();  // restored as it is, not made again from the names
  u(index.size());
  w.array(index.data(), index.size());
  u(linked.size());
  for (auto& [ea, l] : linked) {
    u(ea);
    st.put(w, l.lib);
    st.put(w, l.symbol);
    u(l.has_symbol);
  }
  for (auto* v : {&boundaries_, &align_starts_, &align_ends_}) {
    u(v->size());
    for (u64 x : *v) u(x);
  }
  u(data_names_.size());
  for (u64 x : data_names_) u(x);
  st.put(w, "end");
  BinWriter f;
  f.out = cache_header(SNAPSHOT_MAGIC, key);
  f.put(u64(st.text.size()));
  f.out += st.text;
  f.out += w.out;
  f.put(u64(img.headers.size()));
  f.out += img.headers;
  u64 at = (f.out.size() + 16 + 4095) / 4096 * 4096;
  f.put(at);
  f.put(u64(img.img.size()));
  f.out.resize(at, '\0');
  f.out += img.img;
  write_cache_file(path, f.out);
}

bool Original::load_snapshot(const std::string& path, const std::string& key) {
  std::string head = cache_header(SNAPSHOT_MAGIC, key);
  std::shared_ptr<const MappedFile> file = open_cache_file(path, head);
  if (!file) return false;
  Original o;  // filled, then taken only when the whole file reads
  o.snapshot_ = file;
  std::string_view data = file->view();
  BinReader r(data, head.size());
  bool bad = false;
  auto u = [&] {
    u64 v = 0;
    r.get(v);
    return v;
  };
  // a count of items each at least `min_bytes` long (guards the reservations against a damaged file)
  auto count = [&](size_t min_bytes) {
    u64 n = u();
    if (n > r.left() / min_bytes) bad = true;
    return bad ? 0 : n;
  };
  std::string_view strings = r.take(u());  // the names are views of it
  auto s = [&]() -> std::string_view {     // a string in the table
    u64 off = u(), n = u();
    if (off > strings.size() || strings.size() - off < n) {
      bad = true;
      return {};
    }
    return strings.substr(off, n);
  };
  std::vector<IdaFunction> fs;
  u64 nfs = count(32);
  fs.reserve(nfs);
  for (u64 n = nfs; n--;) {
    IdaFunction f;
    f.ea = u();
    f.size = u();
    f.name = s();
    u64 flags = u();
    f.lib = flags & 1;
    f.thunk = flags & 2;
    fs.push_back(f);
  }
  o.functions.assign(std::move(fs));
  for (u64 n = count(16); n--;) {
    u64 ea = u();
    auto& slots = o.vtables[ea];
    for (u64 k = count(8); k--;) slots.push_back(u());
  }
  u64 names = count(16);
  std::vector<NameTable::Entry> entries;
  entries.reserve(names);
  while (names--) {
    std::string_view name = s();
    entries.emplace_back(name, u());
  }
  std::vector<u32> slots(count(4));
  std::string_view index = r.take(slots.size() * 4);
  if (!r.ok() || bad) return false;
  std::memcpy(slots.data(), index.data(), index.size());
  if (!o.by_name.restore(std::move(entries), std::move(slots))) return false;
  for (u64 n = count(32); n--;) {
    u64 ea = u();
    Linked l;
    l.lib = s();
    l.symbol = s();
    l.has_symbol = u() != 0;
    o.linked[ea] = std::move(l);
  }
  for (auto* v : {&o.boundaries_, &o.align_starts_, &o.align_ends_}) {
    u64 n = count(8);
    v->reserve(n);
    while (n--) v->push_back(u());
  }
  u64 n = count(8);
  o.data_names_.reserve(n);
  while (n--) o.data_names_.push_back(u());
  if (std::adjacent_find(o.data_names_.begin(), o.data_names_.end(), std::greater_equal<u64>()) != o.data_names_.end())
    return false;  // not sorted and distinct
  if (s() != "end" || !r.ok() || bad) return false;
  std::string_view headers = r.take(u());
  u64 at = u(), size = u();
  if (!r.ok() || at % 4096 || at < r.at() || at > data.size() || data.size() - at != size) return false;
  try {
    o.img = Image::laid_out(headers, data.substr(at), o.snapshot_);
  } catch (...) { return false; }
  o.digest = std::move(digest);
  o.config_ = config_;
  o.cache_key_ = cache_key_;
  *this = std::move(o);  // a vector keeps its buffer when moved: the views stay valid
  return true;
}

u64 Original::extent(u64 va) const {
  auto e = img.extent(va);
  if (e && *e) return *e;
  return va + functions.at(va).size;
}

void Original::load_items() {
  std::set<u64> b;
  std::map<u64, u64> align;
  if (file_exists(config_->data_items)) {
    for_each_file_line(config_->data_items, [&](std::string_view line) {
      if (line.find("\"align\"") == std::string_view::npos) return;
      u64 ea, size;
      size_t e;
      static constexpr std::string_view sz = ", \"size\": ";
      // `{"ea": N, "size": M, ...`, or any other JSON
      if (!(lead_ea(line, ea, e) && line.substr(e, sz.size()) == sz && member_int(line, e + sz.size(), size, e))) {
        auto d = json::parse(line);
        ea = u64(d["ea"].as_int());
        size = u64(d["size"].as_int());
      }
      b.insert(ea);
      align[ea] = ea + size;
    });
  }
  if (file_exists(config_->data_names)) {
    for_each_file_line(config_->data_names, [&](std::string_view line) {
      if (line.find("\"kind\": \"data\"") == std::string_view::npos) return;
      u64 ea;
      size_t e;
      if (!lead_ea(line, ea, e)) ea = u64(json::parse(line)["ea"].as_int());
      data_names_.push_back(ea);
    });
  }
  std::sort(data_names_.begin(), data_names_.end());
  data_names_.erase(std::unique(data_names_.begin(), data_names_.end()), data_names_.end());
  for (u64 x : data_names_) b.insert(x);
  boundaries_.assign(b.begin(), b.end());
  for (auto& [s, e] : align) {
    align_starts_.push_back(s);
    align_ends_.push_back(e);
  }
}

u64 Original::object_end(u64 va) const {
  auto it = std::upper_bound(boundaries_.begin(), boundaries_.end(), va);
  return it != boundaries_.end() ? *it : va;
}

bool Original::named_data(u64 va) const { return std::binary_search(data_names_.begin(), data_names_.end(), va); }

bool Original::in_padding(u64 va) const {
  long i = long(std::upper_bound(align_starts_.begin(), align_starts_.end(), va) - align_starts_.begin()) - 1;
  return i >= 0 && va < align_ends_[size_t(i)];
}

// -- Rebuilt -------------------------------------------------------------------------------------------------

Rebuilt::Rebuilt(const std::string& path, const std::string& map_path, NameCache& nc,
                 const std::function<void(const std::string&, std::string_view)>& read)
    : names_(&nc) {
  img = Image::load(path,
                    read ? [&](std::string_view data) { read(path, data); } : std::function<void(std::string_view)>());
  std::vector<std::pair<u64, std::string_view>> syms;  // (address, decorated name) in map order
  std::vector<NameIds> infos;                          // infos[i]: syms[i]'s
  {
    MappedFile map_file(map_path);
    if (read) read(map_path, map_file.view());
    syms = parse_map(map_file.view());
    std::vector<std::string_view> decs;
    decs.reserve(syms.size());
    for (auto& s : syms) decs.push_back(s.second);
    infos = nc.load(decs);
    // the names as the NameCache keeps them, and the map's text freed
    for (size_t i = 0; i < syms.size(); ++i) syms[i].second = nc.text(infos[i].decorated);
  }
  symbols = Symbols(syms);
  // this build's qualified names, numbered in map order; the symbols by that number (counting sort: map order within
  // each)
  u32 nids = nc.string_count();
  std::vector<u32> local(nids, 0);  // NameCache id -> number + 1
  std::vector<u32> first_sym;       // by number: its first symbol
  for (u32 i = 0; i < infos.size(); ++i)
    if (!local[infos[i].qualified]) {
      qual_ids_.push_back(infos[i].qualified);
      first_sym.push_back(i);
      local[infos[i].qualified] = u32(qual_ids_.size());
    }
  u32 nq = u32(qual_ids_.size());
  qual_first_.assign(size_t(nq) + 1, 0);
  for (auto& ni : infos) ++qual_first_[local[ni.qualified]];
  for (u32 q = 0; q < nq; ++q) qual_first_[q + 1] += qual_first_[q];
  qual_syms_.resize(syms.size());
  {
    std::vector<u32> fill(qual_first_.begin(), qual_first_.end() - 1);
    for (size_t i = 0; i < syms.size(); ++i)
      qual_syms_[fill[local[infos[i].qualified] - 1]++] = {syms[i].first, nc.text(infos[i].signature)};
  }
  // the numbers by the ids of their last one and two components (counting sort by id: map order within each)
  {
    std::vector<u32> firsts[2];  // by_last_[n] index of the first with each id
    for (auto& f : firsts) f.assign(size_t(nids) + 1, 0);
    for (u32 q = 0; q < nq; ++q) {  // a qualified name's components are those of its first symbol's
      const NameIds& ni = infos[first_sym[q]];
      ++firsts[0][ni.last1 + 1];
      ++firsts[1][ni.last2 + 1];
    }
    for (auto& f : firsts)
      for (u32 k = 0; k < nids; ++k) f[k + 1] += f[k];
    for (auto& b : by_last_) b.resize(nq);
    for (u32 q = 0; q < nq; ++q) {
      const NameIds& ni = infos[first_sym[q]];
      by_last_[0][firsts[0][ni.last1]++] = {ni.last1, q};
      by_last_[1][firsts[1][ni.last2]++] = {ni.last2, q};
    }
  }
  std::vector<char> code_q(nids);
  std::unordered_map<std::string_view, u64, SvHash> code_by_dec;
  for (size_t i = 0; i < syms.size(); ++i) {
    auto& [va, d] = syms[i];
    if (!img.executable(va)) continue;
    code_q[infos[i].qualified] = 1;
    code_by_dec[d] = va;
  }
  for (size_t i = 0; i < syms.size(); ++i) {
    auto& [va, d] = syms[i];
    if (img.executable(va)) continue;
    if (local_static_match(d) || code_q[infos[i].owner]) local_statics.insert(va);
  }
  for (auto& [va, d] : syms) {
    size_t m = local_statics.count(va) ? local_static_match(d) : 0;
    if (!m) continue;
    // the owner: the function whose decorated name is "?" and the rest up to one of its '@'s (the first that is one)
    std::string_view rest = d.substr(m);
    std::optional<u64> owner;
    std::string probe;
    for (size_t i = 0; i < rest.size() && !owner; ++i) {
      if (rest[i] != '@') continue;
      probe.assign("?").append(rest.substr(0, i));
      if (auto it = code_by_dec.find(std::string_view(probe)); it != code_by_dec.end()) owner = it->second;
    }
    auto& owners = static_owner.try_emplace(va, std::set<u64>()).first->second;
    if (!owner || !owners)
      owners = std::nullopt;
    else
      owners->insert(*owner);
  }
}

std::vector<u32> Rebuilt::matching(const std::string& key) const {
  // `key` names q when it is q or the part of q after one of its "::" (found left to right): then its last one
  // and two components are q's
  std::vector<u32> out;
  if (!names_) return out;
  int n = last_components(key, 1).size() == key.size() ? 1 : 2;
  const auto& b = by_last_[n - 1];
  auto k = names_->id_of(last_components(key, n));
  if (!k) return out;
  for (auto it = std::lower_bound(b.begin(), b.end(), std::pair<u32, u32>{*k, 0}); it != b.end() && it->first == *k;
       ++it) {
    std::string_view q = names_->text(qual_ids_[it->second]);
    bool hit = q == key;
    if (!hit && q.size() > key.size() + 1 && q.ends_with(key))
      for (size_t p = q.find("::"); !hit && p != std::string_view::npos; p = q.find("::", p + 2))
        hit = q.substr(p + 2) == key;
    if (hit) out.push_back(it->second);
  }
  return out;
}

Lookup Rebuilt::lookup(const std::string& key0, const std::optional<std::string>& sig, bool code) const {
  std::string key = norm_name(key0);
  std::vector<u32> hits = matching(key);
  last_.name = key0;  // overloads_of on the same name (pairing asks for both) reads these
  last_.hits = hits;
  std::set<u64> vas;
  for (u32 q : hits) {
    for (u32 k = qual_first_[q]; k < qual_first_[q + 1]; ++k) {
      const QualSym& s = qual_syms_[k];
      if (sig && s.sig != *sig) continue;
      if (code && !img.executable(s.va)) continue;
      vas.insert(s.va);
    }
  }
  return {std::vector<u64>(vas.begin(), vas.end()),
          hits.size() == 1 ? std::string(names_->text(qual_ids_[hits[0]])) : key, hits.size()};
}

std::vector<std::string> Rebuilt::overloads_of(const std::string& key) const {
  std::set<std::string_view> out;
  for (u32 q : key == last_.name ? last_.hits : matching(norm_name(key)))
    for (u32 k = qual_first_[q]; k < qual_first_[q + 1]; ++k)
      if (img.executable(qual_syms_[k].va)) out.insert(qual_syms_[k].sig);
  return std::vector<std::string>(out.begin(), out.end());
}

std::optional<u64> Rebuilt::containing(u64 t) const {
  const auto& vas = symbols.vas();
  auto it = std::upper_bound(vas.begin(), vas.end(), t);
  if (it == vas.begin()) return std::nullopt;
  u64 s = *(it - 1);
  if (t - s < MAX_SYM_OFFSET) return s;
  return std::nullopt;
}

std::optional<u64> Rebuilt::next_symbol(u64 t) const {
  const auto& vas = symbols.vas();
  auto it = std::upper_bound(vas.begin(), vas.end(), t);
  if (it == vas.end()) return std::nullopt;
  return *it;
}

u64 Rebuilt::extent(u64 va) const {
  auto e = img.extent(va);
  if (e) return *e;
  auto nxt = next_symbol(va);
  u64 to = nxt ? *nxt : va + 0x1000;
  auto b = img.bytes(va, i64(to - va));
  size_t n = b.size();
  while (n && static_cast<unsigned char>(b[n - 1]) == 0xcc) --n;
  return va + n;
}

u64 Rebuilt::span(u64 t) const {
  auto nxt = next_symbol(t);
  return std::min<u64>((nxt ? *nxt : t + MAX_DATA_COMPARE) - t, MAX_DATA_COMPARE);
}

std::optional<std::pair<u64, u64>> Rebuilt::local_base(u64 t) const {
  auto base = containing(t);
  if (base && local_statics.count(*base)) return std::make_pair(*base, t - *base);
  return std::nullopt;
}

}  // namespace verifier
