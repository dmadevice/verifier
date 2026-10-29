#include "report.hpp"

#include <algorithm>
#include <map>
#include <optional>
#include <set>
#include <tuple>

namespace verifier {

namespace {

const char* size_name(int n) {
  switch (n) {
    case 1: return "byte";
    case 2: return "word";
    case 4: return "dword";
    case 8: return "qword";
    case 16: return "xmmword";
    default: return "";
  }
}

// a memory operand with its size: "dword [x]", or "[x]" when the size has no name
std::string sized(int size, const std::string& operand) {
  const char* n = size_name(size);
  return *n ? std::string(n) + " " + operand : operand;
}

}  // namespace

Toks symbolise(const std::vector<Insn>& insns, u64 lo, u64 hi, const std::function<Key(u64)>& resolve0, const Image& img,
               bool const_by_value) {
  Toks toks;
  toks.reserve(insns.size());
  i64 flo = i64(lo - img.base), fhi = i64(hi - img.base);
  auto resolve = [&](u64 t) {
    auto it = img.imports.find(t);
    if (it != img.imports.end()) { Key k; k.kind = Key::IMP; k.imp = it->second; return k; }
    return resolve0(t);
  };
  u16 rip = reg_rip();
  for (auto& ins : insns) {
    Tok tok{ins.mnemonic, {}};
    for (auto& op : ins.ops) {
      Op o{};
      if (op.type == OP_REG) {
        o.k = Op::R;
        o.base = reg_name(op.reg);
      } else if (op.type == OP_IMM) {
        if (ins.branches()) {
          i64 t = op.imm;
          if (i64(lo) <= t && t < i64(hi)) { o.k = Op::REL; o.v = t - i64(lo); }
          else { o.k = Op::SYM; o.key = resolve(u64(t)); }
        } else {
          o.k = Op::I;
          o.v = op.imm;
        }
      } else if (op.type == OP_MEM) {
        std::string seg = op.mem.segment ? reg_name(op.mem.segment) : "";
        if (op.mem.base == rip) {
          u64 t = ins.address + ins.size + u64(op.mem.disp);
          Key r = resolve(t);
          if (const_by_value && r.kind == Key::CONST) {
            o.k = Op::CONST;
            o.base = hex_bytes(img.bytes(t, op.size ? op.size : 4));
          } else {
            o.k = Op::MSYM;
            o.key = r;
            o.size = op.size;
          }
        } else if (flo <= op.mem.disp && op.mem.disp < fhi + i64(TABLE_SLACK) && op.mem.index) {
          o.k = Op::TBL;
          o.base = op.mem.base ? reg_name(op.mem.base) : "";
          o.index = reg_name(op.mem.index);
          o.scale = op.mem.scale;
          o.v = op.mem.disp - flo;
          o.size = op.size;
        } else {
          o.k = Op::M;
          o.base = op.mem.base ? reg_name(op.mem.base) : "";
          o.index = op.mem.index ? reg_name(op.mem.index) : "";
          o.scale = op.mem.scale;
          o.v = op.mem.disp;
          o.size = op.size;
          o.seg = seg;
        }
      } else {
        continue;
      }
      tok.ops.push_back(std::move(o));
    }
    toks.push_back(std::move(tok));
  }
  return toks;
}

std::string tok_text(const Tok& tok, const std::unordered_map<u64, std::string>& names) {
  auto target = [&](const Key& r) -> std::string {
    if (r.kind == Key::VA) {
      auto it = names.find(r.va);
      return it != names.end() && !it->second.empty() ? it->second : hex(r.va);
    }
    if (r.kind == Key::IMP) return imp_str(&r.imp);
    return r.name;
  };
  std::vector<std::string> ops;
  for (auto& op : tok.ops) {
    switch (op.k) {
      case Op::R: ops.push_back(op.base); break;
      case Op::I: ops.push_back(hex_signed(op.v)); break;
      case Op::REL: ops.push_back("<+" + hex_signed(op.v) + ">"); break;   // an offset into the function
      case Op::SYM: ops.push_back(target(op.key)); break;
      case Op::MSYM: ops.push_back(sized(op.size, "[" + target(op.key) + "]")); break;
      case Op::CONST: ops.push_back("[const " + op.base.substr(0, 16) + "]"); break;
      case Op::TBL:
        ops.push_back(sized(op.size, "[table+" + hex_signed(op.v) + " + " + op.index + "*" + std::to_string(op.scale) + "]"));
        break;
      case Op::M: {
        std::string addr = op.base;
        std::string idx = op.index.empty() ? "" : op.index + "*" + std::to_string(op.scale);
        if (!idx.empty()) addr = addr.empty() ? idx : addr + "+" + idx;
        if (op.v || addr.empty()) {
          std::string sign = op.v < 0 ? "-" : (addr.empty() ? "" : "+");
          addr += sign + hex(u64(op.v < 0 ? -op.v : op.v));
        }
        ops.push_back(sized(op.size, (op.seg.empty() ? "" : op.seg + ":") + "[" + addr + "]"));
        break;
      }
    }
  }
  return ops.empty() ? tok.mnemonic : tok.mnemonic + " " + join(ops, ", ");
}

std::string classify(const Toks& a, const Toks& b) {
  auto ncalls = [](const Toks& ts) {
    size_t n = 0;
    for (auto& t : ts) n += t.mnemonic == "call" || (t.mnemonic == "jmp" && !t.ops.empty() && t.ops[0].k == Op::SYM);
    return n;
  };
  if (ncalls(a) != ncalls(b)) return "inlining";
  std::vector<std::string> ma, mb;
  for (auto& t : a) ma.push_back(t.mnemonic);
  for (auto& t : b) mb.push_back(t.mnemonic);
  if (ma == mb) {
    size_t n = std::min(a.size(), b.size());
    bool regalloc = true;
    for (size_t i = 0; regalloc && i < n; ++i) {
      auto &x = a[i].ops, &y = b[i].ops;
      if (x.size() != y.size()) { regalloc = false; break; }
      for (size_t k = 0; k < x.size(); ++k) {
        const Op &o = x[k], &p = y[k];
        bool ok = o == p || (o.k == Op::R && p.k == Op::R) ||
                  (o.k == Op::M && p.k == Op::M && o.scale == p.scale && o.v == p.v && o.size == p.size && o.seg == p.seg);
        if (!ok) { regalloc = false; break; }
      }
    }
    if (regalloc) return "regalloc";
    bool kinds = true;
    for (size_t i = 0; kinds && i < n; ++i) {
      auto &x = a[i].ops, &y = b[i].ops;
      if (x.size() != y.size()) { kinds = false; break; }
      for (size_t k = 0; k < x.size(); ++k) if (x[k].k != y[k].k) { kinds = false; break; }
    }
    if (kinds) {
      for (size_t i = 0; i < n; ++i)
        for (size_t k = 0; k < a[i].ops.size(); ++k) {
          const Op &o = a[i].ops[k], &p = b[i].ops[k];
          if (!(o == p) && o.k != Op::SYM && o.k != Op::MSYM) return "immediate";
        }
      return "reference";
    }
    return "unexplained";
  }
  auto sa = ma, sb = mb;
  std::sort(sa.begin(), sa.end());
  std::sort(sb.begin(), sb.end());
  if (sa == sb) return "reorder";
  long d = long(ma.size()) - long(mb.size());
  if (std::labs(d) > std::max<long>(4, long(ma.size()) / 4)) return "inlining";
  return "unexplained";
}

// -- opcodes of a sequence alignment: longest common block first (earliest in a, then in b), recursively on both
// sides; the longest block is found in linear time with a suffix automaton ----------------------------------

namespace {

struct Match { size_t i, j, k; };

// suffix automaton of b[blo:bhi] with edge lists in one pool (the root's transitions in a table by symbol);
// first: where the state's first occurrence in b ends. Symbols are small non-negative ints.
Match longest_match(const std::vector<int>& a, const std::vector<int>& b, size_t alo, size_t ahi, size_t blo, size_t bhi) {
  struct Edge { int c, to, next; };
  struct State { int head; int link; size_t len, first; };
  int nsym = 0;
  for (size_t p = blo; p < bhi; ++p) nsym = std::max(nsym, b[p] + 1);
  std::vector<int> root(size_t(nsym), -1);
  std::vector<State> st;
  std::vector<Edge> edges;
  st.reserve(2 * (bhi - blo) + 1);
  edges.reserve(3 * (bhi - blo) + 1);
  st.push_back({-1, -1, 0, 0});
  auto get = [&](int v, int c) -> int {
    if (v == 0) return c < nsym ? root[size_t(c)] : -1;
    for (int e = st[size_t(v)].head; e != -1; e = edges[size_t(e)].next)
      if (edges[size_t(e)].c == c) return edges[size_t(e)].to;
    return -1;
  };
  auto set = [&](int v, int c, int to) {
    if (v == 0) { root[size_t(c)] = to; return; }
    for (int e = st[size_t(v)].head; e != -1; e = edges[size_t(e)].next)
      if (edges[size_t(e)].c == c) { edges[size_t(e)].to = to; return; }
    edges.push_back({c, to, st[size_t(v)].head});
    st[size_t(v)].head = int(edges.size() - 1);
  };
  int last = 0;
  for (size_t p = blo; p < bhi; ++p) {
    int c = b[p];
    int cur = int(st.size());
    st.push_back({-1, 0, st[size_t(last)].len + 1, p});
    int v = last;
    while (v != -1 && get(v, c) == -1) {
      set(v, c, cur);
      v = st[size_t(v)].link;
    }
    if (v != -1) {
      int q = get(v, c);
      if (st[size_t(q)].len == st[size_t(v)].len + 1) {
        st[size_t(cur)].link = q;
      } else {
        int clone = int(st.size());
        st.push_back({-1, st[size_t(q)].link, st[size_t(v)].len + 1, st[size_t(q)].first});
        if (q == 0) {
          for (int k = 0; k < nsym; ++k) if (root[size_t(k)] != -1) set(clone, k, root[size_t(k)]);
        } else {
          for (int e = st[size_t(q)].head; e != -1; e = edges[size_t(e)].next) set(clone, edges[size_t(e)].c, edges[size_t(e)].to);
        }
        while (v != -1 && get(v, c) == q) {
          set(v, c, clone);
          v = st[size_t(v)].link;
        }
        st[size_t(q)].link = st[size_t(cur)].link = clone;
      }
    }
    last = cur;
  }
  size_t besti = alo, bestj = blo, bestsize = 0;
  int v = 0;
  size_t k = 0;
  for (size_t i = alo; i < ahi; ++i) {
    int c = a[i];
    while (v && get(v, c) == -1) {
      v = st[size_t(v)].link;
      k = st[size_t(v)].len;
    }
    int to = get(v, c);
    if (to != -1) {
      v = to;
      ++k;
      if (k > bestsize) {
        besti = i - k + 1;
        bestj = st[size_t(v)].first - k + 1;
        bestsize = k;
      }
    } else {
      k = 0;
    }
  }
  return {besti, bestj, bestsize};
}

}  // namespace

LongestMatch find_longest_match(const std::vector<int>& a, const std::vector<int>& b, size_t alo, size_t ahi, size_t blo, size_t bhi) {
  Match m = longest_match(a, b, alo, ahi, blo, bhi);
  return {m.i, m.j, m.k};
}

std::vector<Opcode> get_opcodes(const std::vector<int>& a, const std::vector<int>& b) {
  size_t la = a.size(), lb = b.size();
  std::vector<std::tuple<size_t, size_t, size_t, size_t>> queue{{0, la, 0, lb}};
  std::vector<Match> blocks;
  while (!queue.empty()) {
    auto [alo, ahi, blo, bhi] = queue.back();
    queue.pop_back();
    Match x = longest_match(a, b, alo, ahi, blo, bhi);
    if (x.k) {
      blocks.push_back(x);
      if (alo < x.i && blo < x.j) queue.emplace_back(alo, x.i, blo, x.j);
      if (x.i + x.k < ahi && x.j + x.k < bhi) queue.emplace_back(x.i + x.k, ahi, x.j + x.k, bhi);
    }
  }
  std::sort(blocks.begin(), blocks.end(), [](const Match& p, const Match& q) {
    return std::tie(p.i, p.j, p.k) < std::tie(q.i, q.j, q.k);
  });
  std::vector<Match> na;
  size_t i1 = 0, j1 = 0, k1 = 0;
  for (auto& m : blocks) {
    if (i1 + k1 == m.i && j1 + k1 == m.j) {
      k1 += m.k;
    } else {
      if (k1) na.push_back({i1, j1, k1});
      i1 = m.i; j1 = m.j; k1 = m.k;
    }
  }
  if (k1) na.push_back({i1, j1, k1});
  na.push_back({la, lb, 0});
  std::vector<Opcode> out;
  size_t i = 0, j = 0;
  for (auto& m : na) {
    char tag = 0;
    if (i < m.i && j < m.j) tag = 'r';
    else if (i < m.i) tag = 'd';
    else if (j < m.j) tag = 'i';
    if (tag) out.push_back({tag, i, m.i, j, m.j});
    i = m.i + m.k;
    j = m.j + m.k;
    if (m.k) out.push_back({'e', m.i, i, m.j, j});
  }
  return out;
}

std::vector<std::string> insn_diff(const std::vector<Insn>& oi, const std::vector<Insn>& ri, const Toks& ot, const Toks& rt,
                                   const std::unordered_map<u64, std::string>& names, int context, size_t limit) {
  auto index = [](const std::vector<Insn>& insns) {
    std::unordered_map<i64, size_t> m;
    for (size_t k = 0; k < insns.size(); ++k) m[i64(insns[k].address - insns[0].address)] = k;
    return m;
  };
  auto o_at = index(oi), r_at = index(ri);
  // tokens as small ints (equal exactly when the tokens are), branch targets inside the function left open ("rel",)
  struct WildHash {
    size_t operator()(const Tok* t) const {
      size_t h = std::hash<std::string>()(t->mnemonic);
      auto mix = [&](size_t x) { h ^= x + 0x9e3779b97f4a7c15ull + (h << 6) + (h >> 2); };
      for (auto& o : t->ops) {
        mix(o.k);
        if (o.k == Op::REL) continue;
        mix(std::hash<std::string>()(o.base));
        mix(std::hash<std::string>()(o.index));
        mix(std::hash<std::string>()(o.key.name));
        mix(size_t(o.key.va));
        mix(size_t(o.v));
        mix(size_t(o.size) * 31 + size_t(o.scale) * 7 + o.key.kind);
      }
      return h;
    }
  };
  struct WildEq {
    bool operator()(const Tok* x, const Tok* y) const {
      if (x->mnemonic != y->mnemonic || x->ops.size() != y->ops.size()) return false;
      for (size_t i = 0; i < x->ops.size(); ++i) {
        const Op &a = x->ops[i], &b = y->ops[i];
        if (a.k != b.k) return false;
        if (a.k != Op::REL && !(a == b)) return false;
      }
      return true;
    }
  };
  std::unordered_map<const Tok*, int, WildHash, WildEq> ids;
  ids.reserve(ot.size() + rt.size());
  std::vector<int> ia, ib;
  ia.reserve(ot.size());
  ib.reserve(rt.size());
  for (auto& t : ot) ia.push_back(ids.emplace(&t, int(ids.size())).first->second);
  for (auto& t : rt) ib.push_back(ids.emplace(&t, int(ids.size())).first->second);
  auto ops = get_opcodes(ia, ib);
  std::unordered_map<size_t, size_t> aligned;
  for (auto& o : ops)
    if (o.tag == 'e')
      for (size_t i = o.i1, j = o.j1; i < o.i2; ++i, ++j) aligned[i] = j;
  auto same_targets = [&](size_t i, size_t j) {
    auto &x = ot[i].ops, &y = rt[j].ops;
    for (size_t z = 0; z < std::min(x.size(), y.size()); ++z) {
      if (x[z].k != Op::REL) continue;
      std::optional<size_t> A, B;
      if (auto it = o_at.find(x[z].v); it != o_at.end())
        if (auto al = aligned.find(it->second); al != aligned.end()) A = al->second;
      if (auto it = r_at.find(y[z].v); it != r_at.end()) B = it->second;
      if (A != B) return false;
    }
    return true;
  };
  struct Entry { char mark; std::string text; size_t at; };
  std::vector<Entry> entries;
  for (auto& o : ops) {
    if (o.tag == 'e') {
      for (size_t i = o.i1, j = o.j1; i < o.i2; ++i, ++j) {
        if (same_targets(i, j)) {
          entries.push_back({' ', tok_text(ot[i], names), i});
        } else {
          entries.push_back({'-', tok_text(ot[i], names), i});
          entries.push_back({'+', tok_text(rt[j], names), i});
        }
      }
    } else {
      for (size_t i = o.i1; i < o.i2; ++i) entries.push_back({'-', tok_text(ot[i], names), i});
      for (size_t j = o.j1; j < o.j2; ++j) entries.push_back({'+', tok_text(rt[j], names), o.i1});
    }
  }
  std::set<size_t> keep;
  for (size_t c = 0; c < entries.size(); ++c) {
    if (entries[c].mark == ' ') continue;
    size_t lo = c >= size_t(context) ? c - size_t(context) : 0, hi = std::min(entries.size(), c + size_t(context) + 1);
    for (size_t k = lo; k < hi; ++k) keep.insert(k);
  }
  std::vector<std::string> out;
  long prev = -2;
  for (size_t k : keep) {
    if (long(k) != prev + 1) out.push_back("@" + std::to_string(entries[k].at));
    out.push_back(std::string(1, entries[k].mark) + " " + entries[k].text);
    prev = long(k);
  }
  if (out.size() > limit) {
    size_t more = out.size() - limit;
    out.resize(limit);
    out.push_back("... " + std::to_string(more) + " more lines");
  }
  return out;
}

}  // namespace verifier
