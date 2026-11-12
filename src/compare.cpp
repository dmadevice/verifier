#include "compare.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>

namespace verifier {

std::string Key::text() const { return kind == VA ? hex(va) : std::string(name); }

bool Journal::speculate(const std::function<bool()>& attempt) {
  size_t mark = log.size();
  auto undo = [&] {
    for (size_t i = log.size(); i > mark; --i) log[i - 1]();
    log.resize(mark);
  };
  ++active;
  bool ok = false;
  try {
    ok = attempt();
  } catch (...) {
    --active;
    undo();
    throw;
  }
  --active;
  if (!ok)
    undo();
  else if (!active)
    log.resize(mark);  // held by no assumption any more
  return ok;
}

i64 literal_size(const Image& img, u64 start, const Key& key) {
  if (key.kind == Key::TD) return 16 + i64(type_name(img, start).size());  // the name counts its terminator
  if (key.kind == Key::STR) return i64(img.cstring(start, key.wide()).size());
  i64 n = constant_size(key.name);
  return n ? n : 1;
}

// -- same_names: build hashes (`?A0x...@`, `<lambda_...>`) in a rebuilt name stand for one original hash ----------

namespace {

// a name split at its build hashes (`?A0x<hex>@`, `<lambda_<hex>>`): the pieces between them, and the hashes
void split_hashes(const Bytes& s, std::vector<Bytes>& pieces, std::vector<Bytes>& hashes) {
  auto hexc = [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); };
  size_t i = 0, last = 0;
  while (i < s.size()) {
    size_t e = std::string::npos;
    if (s.compare(i, 4, "?A0x") == 0) {
      size_t j = i + 4;
      while (j < s.size() && hexc(s[j])) ++j;
      if (j > i + 4 && j < s.size() && s[j] == '@') e = j + 1;
    } else if (s.compare(i, 8, "<lambda_") == 0) {
      size_t j = i + 8;
      while (j < s.size() && hexc(s[j])) ++j;
      if (j > i + 8 && j < s.size() && s[j] == '>') e = j + 1;
    }
    if (e != std::string::npos) {
      pieces.push_back(s.substr(last, i - last));
      hashes.push_back(s.substr(i, e - i));
      i = last = e;
    } else {
      ++i;
    }
  }
  pieces.push_back(s.substr(last));
}

ComparerContext& nothing_known() {
  static ComparerContext none;
  return none;
}

const std::map<u64, std::vector<u64>>& no_vtables() {
  static const std::map<u64, std::vector<u64>> none;
  return none;
}


}  // namespace

Comparer::Comparer(const Image* o, const Image* r, std::function<Key(u64)> res,
                   const std::map<u64, std::vector<u64>>* vt, NameOf nm, ComparerContext* context)
    : O(o),
      R(r),
      resolve(std::move(res)),
      vtables(vt ? *vt : no_vtables()),
      names(nm ? std::move(nm) : NameOf([](u64) { return std::string_view(); })),
      ctx(context ? context : &nothing_known()) {}

std::shared_ptr<const Code> Comparer::orig_code(u64 start, u64 end) {
  auto c = ctx->orig_code(start, end);
  return c ? c : std::make_shared<const Code>(*O, start, end);
}

std::shared_ptr<const Code> Comparer::rebuilt_code(u64 start, u64 end) {
  auto c = ctx->rebuilt_code(start, end);
  return c ? c : std::make_shared<const Code>(*R, start, end);
}

bool Comparer::same_names(const NamePairs& names) {
  std::vector<std::pair<Bytes, Bytes>> pairs;  // (original hash, rebuilt hash)
  for (auto& [x, y] : names) {
    std::vector<Bytes> px, hx, py, hy;
    split_hashes(x, px, hx);
    split_hashes(y, py, hy);
    if (px != py || hx.size() != hy.size()) return false;
    for (size_t k = 0; k < hx.size(); ++k) pairs.emplace_back(hx[k], hy[k]);
  }
  std::unordered_map<std::string, std::string> new_o, new_r;
  for (auto& [o, r] : pairs) {
    auto get = [](const JMap<std::string, std::string>& m, const std::unordered_map<std::string, std::string>& nw,
                  const std::string& k, const std::string& dflt) {
      if (auto p = m.find(k)) return *p;
      auto it = nw.find(k);
      return it == nw.end() ? dflt : it->second;
    };
    if (get(hash_r, new_r, r, o) != o || get(hash_o, new_o, o, r) != r) return false;
    new_r[r] = o;
    new_o[o] = r;
  }
  for (auto& [o, r] : pairs) {
    if (new_r.count(r)) hash_r.set(r, new_r[r]);
    if (new_o.count(o)) hash_o.set(o, new_o[o]);
  }
  return true;
}

bool Comparer::same_rtti(const Rtti& a, const Rtti& b) {
  if (a.present != b.present) return false;
  if (!a.present) return true;
  if (a.bad_sig || b.bad_sig) return a.bad_sig == b.bad_sig && a.sig == b.sig;
  if (a.off != b.off || a.cdoff != b.cdoff || a.attrs != b.attrs || a.bases.size() != b.bases.size()) return false;
  NamePairs names{{a.name, b.name}};
  for (size_t i = 0; i < a.bases.size(); ++i) {
    const BaseDesc &x = a.bases[i], &y = b.bases[i];
    if (x.ncont != y.ncont || x.mdisp != y.mdisp || x.pdisp != y.pdisp || x.vdisp != y.vdisp || x.attr != y.attr)
      return false;
    names.emplace_back(x.name, y.name);
  }
  return same_names(names);
}

bool Comparer::same_catchables(const ThrowInfoSig& a, const ThrowInfoSig& b) {
  if (a.attrs != b.attrs || a.types.size() != b.types.size()) return false;
  NamePairs names;
  for (size_t i = 0; i < a.types.size(); ++i) {
    const CatchableSig &x = a.types[i], &y = b.types[i];
    if (x.props != y.props || x.mdisp != y.mdisp || x.pdisp != y.pdisp || x.vdisp != y.vdisp || x.size != y.size)
      return false;
    names.emplace_back(x.name, y.name);
  }
  return same_names(names);
}

Problems Comparer::code(u64 ostart, u64 oend, u64 rstart, u64 rend) {
  auto ocp = orig_code(ostart, oend), rcp = rebuilt_code(rstart, rend);
  const Code &oc = *ocp, &rc = *rcp;
  Problems probs;
  auto decoded = [](const Code& c) {
    i64 s = 0;
    for (auto& i : c.insns) s += i.size;
    return s;
  };
  if (!oc.complete || !rc.complete)
    probs.push_back({Category::Undecodable, "decoded " + std::to_string(decoded(oc)) + "/" + std::to_string(oc.cut) + " | " +
                                        std::to_string(decoded(rc)) + "/" + std::to_string(rc.cut) + " code bytes"});
  if (oc.code.size() != rc.code.size() || oc.cut != rc.cut || oc.resume != rc.resume ||
      oc.insns.size() != rc.insns.size()) {
    probs.push_back({Category::Length, std::to_string(oc.code.size()) + "/" + std::to_string(rc.code.size()) + " bytes, code " +
                                   std::to_string(oc.cut) + "/" + std::to_string(rc.cut)});
    return probs;
  }
  for (size_t k = 0; k < oc.insns.size(); ++k) {
    const Lean &a = oc.insns[k], &b = rc.insns[k];
    auto fa = oc.fields(a), fb = rc.fields(b);
    auto enc = [&] { return "@" + std::to_string(k) + ": `" + oc.insn(a).text() + "` | `" + rc.insn(b).text() + "`"; };
    if (!same_layout(a, fa, b, fb) || !same_outside_fields(oc.bytes(a), rc.bytes(b), fa)) {
      probs.push_back({Category::Encoding, enc()});
      continue;
    }
    for (size_t z = 0; z < fa.size(); ++z) {
      if (fa[z].kind == F_TBL) {
        if (fa[z].value != fb[z].value)
          probs.push_back({Category::Encoding, "@" + std::to_string(k) + ": table offset " + hex_signed(fa[z].value) + " vs " +
                                           hex_signed(fb[z].value)});
        continue;
      }
      // an indexed read can be of any part of the object: compared as the whole object, its address taken
      int access = fa[z].indexed || fb[z].indexed ? 0 : fa[z].access;
      auto p = ref(u64(fa[z].value), u64(fb[z].value), access);
      if (p) probs.push_back({p->category, "@" + std::to_string(k) + ": " + p->detail});
    }
  }
  if (!(oc.table_region() == rc.table_region())) probs.push_back({Category::Encoding, "switch table region differs"});
  if (!(oc.outside_tables() == rc.outside_tables()))
    probs.push_back({Category::Encoding, "switch tables after the function differ"});
  return probs;
}


Problems Comparer::function(u64 ostart, u64 oend, u64 rstart, u64 rend, int depth) {
  auto k = std::make_pair(ostart, rstart);
  if (auto m = memo_fn.find(k)) return *m;
  memo_fn.set(k, Problems{});
  Problems probs = code(ostart, oend, rstart, rend);
  if (probs.empty()) probs = unwinds(ostart, oend, rstart, rend, depth);
  memo_fn.set(k, probs);
  return probs;
}

}  // namespace verifier
