#include "inputs.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <filesystem>

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

// The snapshot: the key and the string table (each length-prefixed), then the fields: little-endian u64s, and
// strings as (offset, length) in the table, which holds each distinct string once. Only the table is kept once read.
struct Writer {
  std::string out, strings;
  std::unordered_map<std::string, u64> at;   // string -> offset in `strings`
  void u(u64 v) { out.append(reinterpret_cast<const char*>(&v), 8); }
  void s(std::string_view x) {
    auto [it, fresh] = at.try_emplace(std::string(x), strings.size());
    if (fresh) strings += x;
    u(it->second);
    u(x.size());
  }
  std::string file(std::string_view key) const {
    std::string f;
    for (std::string_view part : {key, std::string_view(strings)}) {
      u64 n = part.size();
      f.append(reinterpret_cast<const char*>(&n), 8);
      f += part;
    }
    return f + out;
  }
};
struct Reader {
  std::string_view in, strings;
  size_t p = 0;
  bool ok = true;
  u64 u() {
    if (!ok || in.size() - p < 8) { ok = false; return 0; }
    u64 v = le64(in.data() + p);
    p += 8;
    return v;
  }
  std::string_view raw() {   // a length-prefixed part
    u64 n = u();
    if (!ok || in.size() - p < n) { ok = false; return {}; }
    std::string_view r = in.substr(p, n);
    p += n;
    return r;
  }
  std::string_view s() {   // a string in the table
    u64 off = u(), n = u();
    if (!ok || off > strings.size() || strings.size() - off < n) { ok = false; return {}; }
    return strings.substr(off, n);
  }
  // a count of items each at least `min_bytes` long (guards the reservations against a damaged file)
  u64 count(size_t min_bytes) {
    u64 n = u();
    if (ok && n > (in.size() - p) / min_bytes) ok = false;
    return ok ? n : 0;
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
  if (it != fs_.end() && it->ea == f.ea) *it = f;
  else fs_.insert(it, f);
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
    if (!fs_.empty() && fs_.back().ea == f.ea) fs_.back() = f;   // the later one
    else fs_.push_back(f);
  }
  fs_.shrink_to_fit();
}

Symbols::Symbols(const std::vector<std::pair<u64, std::string_view>>& syms) {
  // the symbols by address (map order within one), then the addresses in the order of their first symbol
  std::vector<u32> by_addr(syms.size());
  for (u32 i = 0; i < by_addr.size(); ++i) by_addr[i] = i;
  std::stable_sort(by_addr.begin(), by_addr.end(), [&](u32 a, u32 b) { return syms[a].first < syms[b].first; });
  std::vector<std::pair<u32, u64>> first_seen;   // (first symbol, address)
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
  std::string key = snapshot_key(p);
  std::string snapshot = p.cache_dir.empty() ? "" : path_join(p.cache_dir, "original-snapshot.bin");
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
  std::vector<IdaFunction> fs;   // in the file's order
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
  std::string key = "verifier original snapshot 3\n" + p.original_sha256 + "\n";
  for (auto* f : p.snapshot_inputs()) key += file_stamp(*f) + "\n";
  return key;
}

void Original::save_snapshot(const std::string& path, const std::string& key) const {
  Writer w;
  w.u(functions.size());
  for (const IdaFunction& f : functions) {
    w.u(f.ea);
    w.u(f.size);
    w.s(f.name);
    w.u(u64(f.lib) | u64(f.thunk) << 1);
  }
  w.u(vtables.size());
  for (auto& [ea, slots] : vtables) {
    w.u(ea);
    w.u(slots.size());
    for (u64 s : slots) w.u(s);
  }
  w.u(by_name.size());
  for (auto& [name, va] : by_name) { w.s(name); w.u(va); }
  w.u(linked.size());
  for (auto& [ea, l] : linked) { w.u(ea); w.s(l.lib); w.s(l.symbol); w.u(l.has_symbol); }
  for (auto* v : {&boundaries_, &align_starts_, &align_ends_}) {
    w.u(v->size());
    for (u64 x : *v) w.u(x);
  }
  w.u(data_names_.size());
  for (u64 x : data_names_) w.u(x);
  w.s("end");
  // then the image: its headers, and where the laid-out image starts (page-aligned) and its size
  std::string f = w.file(key);
  auto put = [&](u64 v) { f.append(reinterpret_cast<const char*>(&v), 8); };
  put(img.headers.size());
  f += img.headers;
  u64 at = (f.size() + 16 + 4095) / 4096 * 4096;
  put(at);
  put(img.img.size());
  f.resize(at, '\0');
  f += img.img;
  std::error_code ec;
  std::filesystem::create_directories(config_->cache_dir, ec);
  write_file_atomic(path, f);
}

bool Original::load_snapshot(const std::string& path, const std::string& key) {
  if (!file_exists(path)) return false;
  Original o;   // filled, then taken only when the whole file reads
  try { o.snapshot_ = std::make_shared<MappedFile>(path); } catch (...) { return false; }
  std::string_view data = o.snapshot_->view();
  Reader r{data, {}};
  if (r.raw() != key) return false;
  r.strings = r.raw();   // the names are views of it
  std::vector<IdaFunction> fs;
  for (u64 n = r.count(32); n--;) {
    IdaFunction f;
    f.ea = r.u();
    f.size = r.u();
    f.name = r.s();
    u64 flags = r.u();
    f.lib = flags & 1;
    f.thunk = flags & 2;
    fs.push_back(f);
  }
  o.functions.assign(std::move(fs));
  for (u64 n = r.count(16); n--;) {
    u64 ea = r.u();
    auto& slots = o.vtables[ea];
    for (u64 k = r.count(8); k--;) slots.push_back(r.u());
  }
  u64 names = r.count(16);
  o.by_name.reserve(names);
  while (names--) {
    std::string_view name = r.s();
    o.by_name.set(name, r.u());
  }
  for (u64 n = r.count(32); n--;) {
    u64 ea = r.u();
    Linked l;
    l.lib = r.s();
    l.symbol = r.s();
    l.has_symbol = r.u() != 0;
    o.linked[ea] = std::move(l);
  }
  for (auto* v : {&o.boundaries_, &o.align_starts_, &o.align_ends_}) {
    u64 n = r.count(8);
    v->reserve(n);
    while (n--) v->push_back(r.u());
  }
  u64 n = r.count(8);
  o.data_names_.reserve(n);
  while (n--) o.data_names_.push_back(r.u());
  if (std::adjacent_find(o.data_names_.begin(), o.data_names_.end(), std::greater_equal<u64>()) != o.data_names_.end())
    return false;   // not sorted and distinct
  if (r.s() != "end" || !r.ok) return false;
  std::string_view headers = r.raw();
  u64 at = r.u(), size = r.u();
  if (!r.ok || at % 4096 || at < r.p || at > data.size() || data.size() - at != size) return false;
  try {
    o.img = Image::laid_out(headers, data.substr(at), o.snapshot_);
  } catch (...) {
    return false;
  }
  o.digest = std::move(digest);
  o.config_ = config_;
  *this = std::move(o);   // a vector keeps its buffer when moved: the views stay valid
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
  for (auto& [s, e] : align) { align_starts_.push_back(s); align_ends_.push_back(e); }
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

Rebuilt::Rebuilt(const std::string& path, const std::string& map_path, NameCache& nc) : names_(&nc) {
  img = Image::load(path);
  std::vector<std::pair<u64, std::string_view>> syms;   // (address, decorated name) in map order
  std::vector<NameIds> infos;   // infos[i]: syms[i]'s
  {
    MappedFile map_file(map_path);
    syms = parse_map(map_file.view());
    std::vector<std::string_view> decs;
    decs.reserve(syms.size());
    for (auto& s : syms) decs.push_back(s.second);
    infos = nc.load(decs);
    // the names as the NameCache keeps them, and the map's text freed
    for (size_t i = 0; i < syms.size(); ++i) syms[i].second = nc.text(infos[i].decorated);
  }
  symbols = Symbols(syms);
  // the symbols by qualified name (counting sort by id: map order within each)
  u32 nids = nc.string_count();
  qual_first_.assign(size_t(nids) + 1, 0);
  for (auto& ni : infos) ++qual_first_[ni.qualified + 1];
  for (u32 q = 0; q < nids; ++q) qual_first_[q + 1] += qual_first_[q];
  qual_syms_.resize(syms.size());
  {
    std::vector<u32> fill(qual_first_.begin(), qual_first_.end() - 1);
    for (size_t i = 0; i < syms.size(); ++i) qual_syms_[fill[infos[i].qualified]++] = {syms[i].first, nc.text(infos[i].signature)};
  }
  // the qualified names by last one and two components, in map order
  std::vector<char> seen(nids), code_q(nids);
  for (auto& c : by_last_) c.first = c.last = c.next = std::vector<u32>(nids, 0);
  for (auto& ni : infos) {
    u32 q = ni.qualified;
    if (seen[q]) continue;
    seen[q] = 1;
    by_last_[0].add(ni.last1, q);
    by_last_[1].add(ni.last2, q);
  }
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
    if (!owner || !owners) owners = std::nullopt;
    else owners->insert(*owner);
  }
}

void Rebuilt::Chain::add(u32 k, u32 q) {
  if (last[k]) next[last[k] - 1] = q + 1;
  else first[k] = q + 1;
  last[k] = q + 1;
}

std::vector<u32> Rebuilt::matching(const std::string& key) const {
  // `key` names q when it is q or the part of q after one of its "::" (found left to right): then its last one
  // and two components are q's
  std::vector<u32> out;
  if (!names_) return out;
  int n = last_components(key, 1).size() == key.size() ? 1 : 2;
  const Chain& c = by_last_[n - 1];
  auto k = names_->id_of(last_components(key, n));
  if (!k || *k >= c.first.size()) return out;
  for (u32 q1 = c.first[*k]; q1; q1 = c.next[q1 - 1]) {
    std::string_view q = names_->text(q1 - 1);
    bool hit = q == key;
    if (!hit && q.size() > key.size() + 1 && q.ends_with(key))
      for (size_t p = q.find("::"); !hit && p != std::string_view::npos; p = q.find("::", p + 2)) hit = q.substr(p + 2) == key;
    if (hit) out.push_back(q1 - 1);
  }
  return out;
}

Lookup Rebuilt::lookup(const std::string& key0, const std::optional<std::string>& sig, bool code) const {
  std::string key = norm_name(key0);
  std::vector<u32> hits = matching(key);
  std::set<u64> vas;
  for (u32 q : hits) {
    for (u32 k = qual_first_[q]; k < qual_first_[q + 1]; ++k) {
      const QualSym& s = qual_syms_[k];
      if (sig && s.sig != *sig) continue;
      if (code && !img.executable(s.va)) continue;
      vas.insert(s.va);
    }
  }
  return {std::vector<u64>(vas.begin(), vas.end()), hits.size() == 1 ? std::string(names_->text(hits[0])) : key, hits.size()};
}

std::vector<std::string> Rebuilt::overloads_of(const std::string& key) const {
  std::set<std::string_view> out;
  for (u32 q : matching(norm_name(key)))
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
