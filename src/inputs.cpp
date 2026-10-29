#include "inputs.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>

#include "json.hpp"
#include "sha256.hpp"

namespace verifier {

namespace {

// `{"ea": <int>` at the start of a JSON line (IDA's exports write "ea" first): its value, and where it ends
bool lead_ea(std::string_view line, u64& ea, size_t& end) {
  static constexpr std::string_view head = "{\"ea\": ";
  if (line.substr(0, head.size()) != head) return false;
  size_t i = head.size(), j = i;
  u64 v = 0;
  while (j < line.size() && line[j] >= '0' && line[j] <= '9') v = v * 10 + u64(line[j++] - '0');
  if (j == i || j - i > 19 || j >= line.size() || (line[j] != ',' && line[j] != '}')) return false;
  ea = v;
  end = j;
  return true;
}

// the snapshot's fields: little-endian u64s and length-prefixed strings
struct Writer {
  std::string out;
  void u(u64 v) { out.append(reinterpret_cast<const char*>(&v), 8); }
  void s(std::string_view x) { u(x.size()); out.append(x); }
};
struct Reader {
  std::string_view in;
  size_t p = 0;
  bool ok = true;
  u64 u() {
    if (!ok || in.size() - p < 8) { ok = false; return 0; }
    u64 v = le64(in.data() + p);
    p += 8;
    return v;
  }
  std::string_view s() {
    u64 n = u();
    if (!ok || in.size() - p < n) { ok = false; return {}; }
    std::string_view r = in.substr(p, n);
    p += n;
    return r;
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
    f.name = v["name"].as_str();
    f.lib = v["lib"].as_bool();
    f.thunk = v["thunk"].as_bool();
    if (!functions.count(f.ea)) function_order.push_back(f.ea);
    functions[f.ea] = f;
  });
  for (u64 ea : function_order) ida_names[ea] = functions[ea].name;
  std::vector<json::Value> matches;
  if (file_exists(p.library_matches)) {
    auto doc = json::parse(read_file(p.library_matches));
    matches = doc["matches"].arr;
  }
  for (u64 ea : function_order) by_name[functions[ea].name] = ea;
  if (file_exists(p.vtables)) {
    for (auto& line : read_lines(p.vtables)) {
      if (strip(line).empty()) continue;
      auto v = json::parse(line);
      u64 ea = u64(v["vtable_ea"].as_int());
      by_name[v["name"].as_str()] = ea;
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
    if (e2s[ea].size() == 1 && (it == by_name.end() || it->second == ea)) by_name[sym] = ea;
  }
  if (file_exists(p.symbols)) {
    for (auto& line : read_lines(p.symbols)) {
      if (strip(line).empty() || starts_with(line, "#")) continue;
      auto w = split_ws(line);
      by_name[w[0]] = parse_hex(w[1]);
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
  std::string key = "verifier original snapshot 1\n";
  for (auto* f : {&p.original, &p.functions, &p.vtables, &p.data_items, &p.data_names, &p.library_matches,
                  &p.library_functions, &p.symbols})
    key += file_stamp(*f) + "\n";
  return key;
}

void Original::save_snapshot(const std::string& path, const std::string& key) const {
  Writer w;
  w.s(key);
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
  std::string tmp = path + ".tmp";
  {
    std::ofstream f(tmp, std::ios::binary);
    if (!f) return;
    f << w.out;
    if (!f) return;
  }
  std::filesystem::rename(tmp, path, ec);   // readers see the old file or the new one
}

bool Original::load_snapshot(const std::string& path, const std::string& key) {
  if (!file_exists(path)) return false;
  std::string data;
  try { data = read_file(path); } catch (...) { return false; }
  Reader r{data};
  if (r.s() != key) return false;
  Original o;   // filled, then taken only when the whole file reads
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
    o.by_name.emplace(std::string(name), r.u());
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
  functions = std::move(o.functions);
  function_order = std::move(o.function_order);
  ida_names = std::move(o.ida_names);
  by_name = std::move(o.by_name);
  vtables = std::move(o.vtables);
  linked = std::move(o.linked);
  boundaries_ = std::move(o.boundaries_);
  align_starts_ = std::move(o.align_starts_);
  align_ends_ = std::move(o.align_ends_);
  data_names_ = std::move(o.data_names_);
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
      bool fast = lead_ea(line, ea, e) && line.substr(e, sz.size()) == sz;
      if (fast) {   // `{"ea": N, "size": M, ...`
        size_t i = e + sz.size(), j = i;
        size = 0;
        while (j < line.size() && line[j] >= '0' && line[j] <= '9') size = size * 10 + u64(line[j++] - '0');
        fast = j > i && j - i <= 19 && j < line.size() && (line[j] == ',' || line[j] == '}');
      }
      if (!fast) {
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
  syms = parse_map(map_path);
  std::vector<std::string_view> decs;
  decs.reserve(syms.size());
  for (auto& s : syms) decs.push_back(s.second);
  std::vector<const NameInfo*> infos = nc.load(decs);   // infos[i]: syms[i]'s
  decs = {};
  for (size_t i = 0; i < syms.size(); ++i) {
    auto& [va, dec] = syms[i];
    auto& v = by_va[va];
    if (v.empty()) by_va_order.push_back(va);
    v.push_back(dec);
    const NameInfo& ni = *infos[i];
    std::string_view q = ni.qualified;
    auto& qv = qual_to_va[q];
    if (qv.empty()) qual_order.push_back(q);
    qv.push_back(va);
    auto& sv = sigs_of[{q, va}];
    std::string_view sig = ni.signature;
    auto at = std::lower_bound(sv.begin(), sv.end(), sig);
    if (at == sv.end() || *at != sig) sv.insert(at, sig);
  }
  sym_vas = by_va_order;
  std::sort(sym_vas.begin(), sym_vas.end());
  for (auto q : qual_order) {
    by_suffix[q].push_back(q);
    for (size_t p = q.find("::"); p != std::string_view::npos; p = q.find("::", p + 2)) by_suffix[q.substr(p + 2)].push_back(q);
  }
  std::unordered_set<std::string_view, SvHash> code_names;
  SvMap<u64> code_by_dec;
  for (size_t i = 0; i < syms.size(); ++i) {
    auto& [va, d] = syms[i];
    if (!img.executable(va)) continue;
    code_names.insert(infos[i]->qualified);
    code_by_dec[d] = va;
  }
  for (size_t i = 0; i < syms.size(); ++i) {
    auto& [va, d] = syms[i];
    if (img.executable(va)) continue;
    if (local_static_match(d) || code_names.count(infos[i]->owner)) local_statics.insert(va);
  }
  for (auto& [va, d] : syms) {
    size_t m = local_statics.count(va) ? local_static_match(d) : 0;
    if (!m) continue;
    std::string rest = d.substr(m);
    std::optional<size_t> k;
    std::string probe;
    for (size_t i = 0; i < rest.size(); ++i) {
      if (rest[i] != '@') continue;
      probe.assign("?").append(rest, 0, i);
      if (code_by_dec.count(probe)) { k = i; break; }
    }
    auto it = static_owner.find(va);
    if (it == static_owner.end()) it = static_owner.emplace(va, std::set<u64>()).first;
    if (!k || !it->second) it->second = std::nullopt;
    else it->second->insert(code_by_dec["?" + rest.substr(0, *k)]);
  }
}

Lookup Rebuilt::lookup(const std::string& key0, const std::optional<std::string>& sig, bool code) const {
  std::string key = norm_name(key0);
  auto it = by_suffix.find(key);
  static const std::vector<std::string_view> none;
  const auto& hits = it == by_suffix.end() ? none : it->second;
  std::set<u64> vas;
  for (auto& q : hits) {
    for (u64 va : qual_to_va.at(q)) {
      if (sig) {
        auto s = sigs_of.find({q, va});
        if (s == sigs_of.end() || !std::binary_search(s->second.begin(), s->second.end(), std::string_view(*sig))) continue;
      }
      if (code && !img.executable(va)) continue;
      vas.insert(va);
    }
  }
  return {std::vector<u64>(vas.begin(), vas.end()), hits.size() == 1 ? std::string(hits[0]) : key, hits.size()};
}

std::vector<std::string> Rebuilt::overloads_of(const std::string& key) const {
  auto it = by_suffix.find(norm_name(key));
  std::set<std::string_view> out;
  if (it != by_suffix.end())
    for (auto& q : it->second)
      for (u64 va : qual_to_va.at(q))
        if (img.executable(va))
          for (auto& s : sigs_of.at({q, va})) out.insert(s);
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
