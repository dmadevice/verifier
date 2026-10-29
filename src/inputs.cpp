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

// a file's identity for the snapshot key: its path, size and modification time ("-" when it does not exist)
std::string file_stamp(const std::string& path) {
  std::error_code ec;
  auto size = std::filesystem::file_size(path, ec);
  if (ec) return path + "\t-";
  auto time = std::filesystem::last_write_time(path, ec);
  if (ec) return path + "\t-";
  return path + "\t" + std::to_string(size) + "\t" + std::to_string(time.time_since_epoch().count());
}

}  // namespace

// -- Original ------------------------------------------------------------------------------------------------

Original::Original(const Config& p) : config_(&p) {
  if (!file_exists(p.original)) {
    std::fprintf(stderr, "verifier: no original binary %s\n", p.original.c_str());
    std::exit(2);
  }
  if (!p.original_sha256.empty()) {
    digest = p.original_sha256;
    if (sha256_file(p.original) != digest) {
      std::fprintf(stderr, "original image hash mismatch: %s is not %s\n", p.original.c_str(), digest.c_str());
      std::exit(1);
    }
  }
  img = Image::load(p.original);
  // the tables below come from the text exports, which rarely change: a snapshot of them is kept in the cache
  std::string snapshot = p.cache_dir.empty() ? "" : path_join(p.cache_dir, "original-snapshot.bin");
  std::string key = snapshot_key(p);
  if (!snapshot.empty() && load_snapshot(snapshot, key)) return;
  load_exports();
  if (!snapshot.empty()) save_snapshot(snapshot, key);
}

void Original::load_exports() {
  const Config& p = *config_;
  for_each_file_line(p.functions, [&](std::string_view line) {
    if (strip(line).empty()) return;
    auto v = json::parse(line);
    IdaFunction f;
    f.ea = u64(v["ea"].as_int());
    f.size = u64(v["size"].as_int());
    f.name = keep(v["name"].as_str());
    f.lib = v["lib"].as_bool();
    f.thunk = v["thunk"].as_bool();
    if (!functions.count(f.ea)) function_order.push_back(f.ea);
    functions[f.ea] = f;
  });
  for (u64 ea : function_order) {
    ida_names[ea] = functions[ea].name;
    by_name[functions[ea].name] = ea;
  }
  std::vector<json::Value> matches;
  if (file_exists(p.library_matches)) matches = json::parse(read_file(p.library_matches))["matches"].arr;
  if (file_exists(p.vtables)) {
    for (auto& line : read_lines(p.vtables)) {
      if (strip(line).empty()) continue;
      auto v = json::parse(line);
      u64 ea = u64(v["vtable_ea"].as_int());
      by_name[keep(v["name"].as_str())] = ea;
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
    auto it = by_name.find(sym);
    if (e2s[ea].size() == 1 && (it == by_name.end() || it->second == ea)) by_name[keep(sym)] = ea;
  }
  if (file_exists(p.symbols)) {
    for (auto& line : read_lines(p.symbols)) {
      if (strip(line).empty() || starts_with(line, "#")) continue;
      auto w = split_ws(line);
      by_name[keep(w[0])] = parse_hex(w[1]);
    }
  }
  by_name["__ImageBase"] = img.base;
  for (auto& m : matches) {
    u64 ea = u64(m["ea"].as_int());
    if (!functions.count(ea)) continue;
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
  std::string key = "verifier original snapshot 2\n";
  for (auto* f : {&p.original, &p.functions, &p.vtables, &p.data_items, &p.data_names, &p.library_matches,
                  &p.library_functions, &p.symbols})
    key += file_stamp(*f) + "\n";
  return key;
}

void Original::save_snapshot(const std::string& path, const std::string& key) const {
  Writer w;
  w.u(function_order.size());
  for (u64 ea : function_order) {
    const IdaFunction& f = functions.at(ea);
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
  std::error_code ec;
  std::filesystem::create_directories(config_->cache_dir, ec);
  write_file_atomic(path, w.file(key));
}

bool Original::load_snapshot(const std::string& path, const std::string& key) {
  if (!file_exists(path)) return false;
  std::string data;
  try { data = read_file(path); } catch (...) { return false; }
  Reader r{data, {}};
  if (r.raw() != key) return false;
  Original o;   // filled, then taken only when the whole file reads
  std::string_view strings = r.raw();
  o.snapshot_.assign(strings.begin(), strings.end());   // the names are views of it
  r.strings = std::string_view(o.snapshot_.data(), o.snapshot_.size());
  for (u64 n = r.count(32); n--;) {
    IdaFunction f;
    f.ea = r.u();
    f.size = r.u();
    f.name = r.s();
    u64 flags = r.u();
    f.lib = flags & 1;
    f.thunk = flags & 2;
    o.function_order.push_back(f.ea);
    o.ida_names[f.ea] = f.name;
    o.functions[f.ea] = std::move(f);
  }
  for (u64 n = r.count(16); n--;) {
    u64 ea = r.u();
    auto& slots = o.vtables[ea];
    for (u64 k = r.count(8); k--;) slots.push_back(r.u());
  }
  for (u64 n = r.count(16); n--;) {
    std::string_view name = r.s();
    o.by_name.emplace(name, r.u());
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
  while (n--) o.data_names_.insert(r.u());
  if (r.s() != "end" || !r.ok || r.p != data.size()) return false;
  o.digest = std::move(digest);
  o.img = std::move(img);
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
      data_names_.insert(ea);
    });
  }
  for (u64 x : data_names_) b.insert(x);
  boundaries_.assign(b.begin(), b.end());
  for (auto& [s, e] : align) { align_starts_.push_back(s); align_ends_.push_back(e); }
}

u64 Original::object_end(u64 va) const {
  auto it = std::upper_bound(boundaries_.begin(), boundaries_.end(), va);
  return it != boundaries_.end() ? *it : va;
}

bool Original::named_data(u64 va) const { return data_names_.count(va) != 0; }

bool Original::in_padding(u64 va) const {
  long i = long(std::upper_bound(align_starts_.begin(), align_starts_.end(), va) - align_starts_.begin()) - 1;
  return i >= 0 && va < align_ends_[size_t(i)];
}

// -- Rebuilt -------------------------------------------------------------------------------------------------

Rebuilt::Rebuilt(const std::string& path, const std::string& map_path, NameCache& nc) : names_(&nc) {
  img = Image::load(path);
  std::vector<NameIds> infos;   // infos[i]: syms[i]'s
  {
    std::string map_text = read_file(map_path);
    syms = parse_map(map_text);
    std::vector<std::string_view> decs;
    decs.reserve(syms.size());
    for (auto& s : syms) decs.push_back(s.second);
    infos = nc.load(decs);
    // the names as the NameCache keeps them, and the map's text freed
    for (size_t i = 0; i < syms.size(); ++i) syms[i].second = nc.text(infos[i].decorated);
  }
  by_va.reserve(syms.size());
  for (auto& [va, dec] : syms) {
    auto& v = by_va[va];
    if (v.empty()) by_va_order.push_back(va);
    v.push_back(dec);
  }
  sym_vas = by_va_order;
  std::sort(sym_vas.begin(), sym_vas.end());
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
  auto it = std::upper_bound(sym_vas.begin(), sym_vas.end(), t);
  if (it == sym_vas.begin()) return std::nullopt;
  u64 s = *(it - 1);
  if (t - s < MAX_SYM_OFFSET) return s;
  return std::nullopt;
}

std::optional<u64> Rebuilt::next_symbol(u64 t) const {
  auto it = std::upper_bound(sym_vas.begin(), sym_vas.end(), t);
  if (it == sym_vas.end()) return std::nullopt;
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
