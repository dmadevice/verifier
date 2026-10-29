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
  for_each_file_line(p.functions, [&](std::string_view line) {
    if (strip(line).empty()) return;
    auto v = json::parse(line);
    IdaFunction f;
    f.ea = u64(v["ea"].as_int());
    f.size = u64(v["size"].as_int());
    f.name = v["name"].as_str();
    f.lib = v["lib"].truthy();
    f.thunk = v["thunk"].truthy();
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
    if (!linked.count(ea)) linked_order.push_back(ea);
    linked[ea] = Linked{m["lib"].as_str(), m["symbol"].as_str(), true};
  }
  if (file_exists(p.library_functions)) {
    auto doc = json::parse(read_file(p.library_functions));
    for (auto& m : doc.arr) {
      u64 ea = u64(m["ea"].as_int());
      if (!linked.count(ea)) linked_order.push_back(ea);
      linked[ea] = Linked{m["lib"].as_str(), "", false};
    }
  }
  load_items();
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
  nc.load(decs);
  decs = {};
  for (auto& [va, dec] : syms) {
    auto& v = by_va[va];
    if (v.empty()) by_va_order.push_back(va);
    v.push_back(dec);
    const NameInfo& ni = nc.info(dec);
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
  std::unordered_set<std::string_view> code_names;
  SvMap<u64> code_by_dec;
  for (auto& [va, d] : syms) {
    if (!img.executable(va)) continue;
    code_names.insert(nc.info(d).qualified);
    code_by_dec[d] = va;
  }
  for (auto& [va, d] : syms) {
    if (img.executable(va)) continue;
    if (local_static_match(d) || code_names.count(nc.info(d).owner)) local_statics.insert(va);
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
  if (test.lookup) return test.lookup(key0, sig, code);
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
  if (test.extent) return test.extent(va);
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
  if (test.span) return test.span(t);
  auto nxt = next_symbol(t);
  return std::min<u64>((nxt ? *nxt : t + MAX_DATA_COMPARE) - t, MAX_DATA_COMPARE);
}

std::optional<std::pair<u64, u64>> Rebuilt::local_base(u64 t) const {
  if (test.local_base) return test.local_base(t);
  auto base = containing(t);
  if (base && local_statics.count(*base)) return std::make_pair(*base, t - *base);
  return std::nullopt;
}

}  // namespace verifier
