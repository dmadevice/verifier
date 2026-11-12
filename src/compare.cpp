#include "compare.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <stdexcept>

namespace verifier {

std::string Key::text() const { return kind == VA ? hex(va) : std::string(name); }

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

void Comparer::explore(const std::vector<FnPair>& functions, const std::vector<std::pair<u64, u64>>& data) {
  for (auto& f : functions) function(f);
  for (auto& [o, r] : data) rodata(o, r);
  explore_queued();
}

void Comparer::explore_queued() {
  for (auto q = m.take_queued(); !q.empty(); q = m.take_queued())
    for (auto& [o, r] : q)
      if (auto f = ctx->function_candidate(o, r)) function(*f);
}

void Comparer::solve() {
  Matching::Rules rules;
  rules.folded_locals = [this](u64 base) { return ctx->folded_locals(base); };
  rules.folded_extra = [this](u64 base, u64 o_primary, u64 o_base) { return folded_extra(base, o_primary, o_base); };
  m.solve(rules);
}

Problems Comparer::judge_function(const FnPair& f) {
  if (!m.solved()) throw std::logic_error("judge before solve");
  return m.judge_root(Kind::Function, f.ostart, f.rstart, [&] { return function_body(f, std::nullopt); });
}

std::optional<Problem> Comparer::judge_rodata(u64 o_t, u64 r_t) {
  if (!m.solved()) throw std::logic_error("judge before solve");
  Problems p = m.judge_root(Kind::Data, o_t, r_t, [&] {
    auto x = rodata_body(o_t, r_t);
    return x ? Problems{*x} : Problems{};
  });
  return p.empty() ? std::nullopt : std::optional<Problem>(p[0]);
}

std::vector<Problems> Comparer::check(const std::vector<FnPair>& roots) {
  explore(roots);
  solve();
  std::vector<Problems> out;
  for (auto& f : roots) out.push_back(judge_function(f));
  return out;
}

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
  // each (original hash, rebuilt hash) a guess: one original hash for each rebuilt one (Matching)
  bool ok = true;
  for (auto& [o, r] : pairs) ok = m.assume(Kind::Hash, m.text_id(o), m.text_id(r)) && ok;
  return ok;
}

bool Comparer::same_signature(const Signature& a, const Signature& b) {
  if (a.values != b.values || a.names.size() != b.names.size()) return false;
  NamePairs names;
  for (size_t i = 0; i < a.names.size(); ++i) names.emplace_back(a.names[i], b.names[i]);
  return same_names(names);
}

Problems Comparer::code(const FnPair& f) {
  auto ocp = orig_code(f.ostart, f.oend);
  const Code& oc = *ocp;
  // the rebuilt code decodes as the original's (same_code_fields): only what the fields refer to is compared. A
  // difference is reported as the full comparison finds it.
  if (auto rf = same_code_fields(oc, *R, f.rstart, f.rend)) {
    Problems probs;
    for (size_t k = 0; k < oc.insns.size(); ++k)
      for (size_t z = oc.insns[k].field; z < size_t(oc.insns[k].field + oc.insns[k].nfields); ++z) {
        const Field &a = oc.field_list[z], &b = (*rf)[z];
        if (auto p = ref(u64(a.value), u64(b.value), a.access))
          probs.push_back({p->category, "@" + std::to_string(k) + ": " + p->detail});
      }
    if (probs.empty() && check_fast_path() && !code_decoded(f, oc).empty())
      throw std::logic_error("fast path: a match the full comparison does not make at " + hex(f.ostart));
    if (probs.empty()) return probs;
  }
  return code_decoded(f, oc);
}

Problems Comparer::code_decoded(const FnPair& f, const Code& oc) {
  auto rcp = rebuilt_code(f.rstart, f.rend);
  const Code& rc = *rcp;
  Problems probs;
  auto decoded = [](const Code& c) {
    i64 s = 0;
    for (auto& i : c.insns) s += i.size;
    return s;
  };
  if (!oc.complete || !rc.complete)
    probs.push_back({Category::Undecodable, "decoded " + std::to_string(decoded(oc)) + "/" + std::to_string(oc.cut) +
                                                " | " + std::to_string(decoded(rc)) + "/" + std::to_string(rc.cut) +
                                                " code bytes"});
  if (oc.code.size() != rc.code.size() || oc.cut != rc.cut || oc.resume != rc.resume ||
      oc.insns.size() != rc.insns.size()) {
    probs.push_back({Category::Length, std::to_string(oc.code.size()) + "/" + std::to_string(rc.code.size()) +
                                           " bytes, code " + std::to_string(oc.cut) + "/" + std::to_string(rc.cut)});
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
          probs.push_back({Category::Encoding, "@" + std::to_string(k) + ": table offset " + hex_signed(fa[z].value) +
                                                   " vs " + hex_signed(fb[z].value)});
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

Problems Comparer::function_body(const FnPair& f, std::optional<std::pair<u64, u64>> fi) {
  Problems probs = code(f);
  if (probs.empty()) probs = unwinds(f, fi);
  return probs;
}

Problems Comparer::function(const FnPair& f) {
  return m.unit(Kind::Function, f.ostart, f.rstart, [&] { return function_body(f, std::nullopt); });
}

// a funclet of a function with FuncInfo `fi`: its own unit (its handler data is that FuncInfo, compared with the
// function, not again here)
Problems Comparer::funclet(const FnPair& f, std::pair<u64, u64> fi) {
  return m.unit(Kind::Funclet, f.ostart, f.rstart, [&] { return function_body(f, fi); });
}

}  // namespace verifier
