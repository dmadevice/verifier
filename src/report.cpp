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

// symbolise_one() into a fresh token
void symbolise_into(Tok& tok, const Insn& ins, u64 lo, u64 hi, const std::function<Key(u64)>& resolve0, const Image& img,
                    bool const_by_value) {
  i64 flo = i64(lo - img.base), fhi = i64(hi - img.base);
  auto resolve = [&](u64 t) {
    auto it = img.imports.find(t);
    if (it != img.imports.end()) { Key k; k.kind = Key::IMP; k.imp = &it->second; return k; }
    return resolve0(t);
  };
  u16 rip = reg_rip();
  tok.mnemonic = ins.mnemonic;
  for (auto& op : ins.ops) {
    Op o{};
    if (op.type == OP_REG) {
      o.k = Op::R;
      o.base = reg_canon(op.reg);
    } else if (op.type == OP_IMM) {
      if (ins.branches()) {
        i64 t = op.imm();
        if (i64(lo) <= t && t < i64(hi)) { o.k = Op::REL; o.v = t - i64(lo); }
        else { o.k = Op::SYM; o.key = resolve(u64(t)); }
      } else {
        o.k = Op::I;
        o.v = op.imm();
      }
    } else if (op.type == OP_MEM) {
      if (op.base() == rip) {
        u64 t = ins.address + ins.size + u64(op.disp());
        Key r = resolve(t);
        if (const_by_value && r.kind == Key::CONST) {
          o.k = Op::CONST;
          o.bytes = img.bytes(t, op.size ? op.size : 4);
        } else {
          o.k = Op::MSYM;
          o.key = r;
          o.size = op.size;
        }
      } else {
        bool table = flo <= op.disp() && op.disp() < fhi + i64(TABLE_SLACK) && op.index;
        o.k = table ? Op::TBL : Op::M;
        o.base = reg_canon(op.base());
        o.index = reg_canon(op.index);
        o.scale = op.scale;
        o.v = table ? op.disp() - flo : op.disp();
        o.size = op.size;
        if (!table) o.seg = reg_canon(segment_reg(op));
      }
    } else {
      continue;
    }
    tok.ops.push_back(o);
  }
}

}  // namespace

Tok symbolise_one(const Insn& ins, u64 lo, u64 hi, const std::function<Key(u64)>& resolve, const Image& img,
                  bool const_by_value) {
  Tok tok;
  symbolise_into(tok, ins, lo, hi, resolve, img, const_by_value);
  return tok;
}

Toks symbolise(const std::vector<Insn>& insns, u64 lo, u64 hi, const std::function<Key(u64)>& resolve, const Image& img,
               bool const_by_value) {
  Toks toks(insns.size());
  for (size_t k = 0; k < insns.size(); ++k) symbolise_into(toks[k], insns[k], lo, hi, resolve, img, const_by_value);
  return toks;
}

std::string tok_text(const Tok& tok, const NameMap& names) {
  std::string out = tok.mnemonic.str();
  auto target = [&](const Key& r) {
    if (r.kind == Key::VA) {
      auto it = names.find(r.va);
      out += it != names.end() && !it->second.empty() ? it->second : hex(r.va);
    } else {
      out += r.kind == Key::IMP ? imp_str(r.imp) : r.name;
    }
  };
  auto size_of = [&](int size) {   // a memory operand's size: "dword [x]", or "[x]" when the size has no name
    const char* n = size_name(size);
    if (*n) { out += n; out += ' '; }
  };
  for (size_t i = 0; i < tok.ops.size(); ++i) {
    const Op& op = tok.ops[i];
    out += i ? ", " : " ";
    switch (op.k) {
      case Op::R: out += reg_name(op.base); break;
      case Op::I: out += hex_signed(op.v); break;
      case Op::REL: out += "<+" + hex_signed(op.v) + ">"; break;   // an offset into the function
      case Op::SYM: target(op.key); break;
      case Op::MSYM: size_of(op.size); out += '['; target(op.key); out += ']'; break;
      case Op::CONST: out += "[const "; out += hex_bytes(op.bytes.substr(0, 8)); out += ']'; break;
      case Op::TBL:
        size_of(op.size);
        out += "[table+" + hex_signed(op.v) + " + " + reg_name(op.index) + "*" + std::to_string(op.scale) + "]";
        break;
      case Op::M: {
        size_of(op.size);
        if (op.seg) { out += reg_name(op.seg); out += ':'; }
        out += '[';
        const char* base = reg_name(op.base);
        out += base;
        bool empty = !*base;
        if (op.index) {
          if (!empty) out += '+';
          out += reg_name(op.index);
          out += '*' + std::to_string(op.scale);
          empty = false;
        }
        if (op.v || empty) {
          out += op.v < 0 ? "-" : empty ? "" : "+";
          out += hex(u64(op.v < 0 ? -op.v : op.v));
        }
        out += ']';
        break;
      }
    }
  }
  return out;
}

std::string classify(const Toks& a, const Toks& b) {
  auto ncalls = [](const Toks& ts) {
    size_t n = 0;
    for (auto& t : ts) n += t.mnemonic == "call" || (t.mnemonic == "jmp" && !t.ops.empty() && t.ops[0].k == Op::SYM);
    return n;
  };
  if (ncalls(a) != ncalls(b)) return "inlining";
  std::vector<std::string_view> ma, mb;
  for (auto& t : a) ma.push_back(t.mnemonic);
  for (auto& t : b) mb.push_back(t.mnemonic);
  if (ma == mb) {
    size_t n = std::min(a.size(), b.size());
    auto all_ops = [&](auto same) {   // every instruction has as many operands, each pair `same`
      for (size_t i = 0; i < n; ++i) {
        auto &x = a[i].ops, &y = b[i].ops;
        if (x.size() != y.size()) return false;
        for (size_t k = 0; k < x.size(); ++k) if (!same(x[k], y[k])) return false;
      }
      return true;
    };
    if (all_ops([](const Op& o, const Op& p) {
          return o == p || (o.k == Op::R && p.k == Op::R) ||
                 (o.k == Op::M && p.k == Op::M && o.scale == p.scale && o.v == p.v && o.size == p.size && o.seg == p.seg);
        }))
      return "regalloc";
    if (!all_ops([](const Op& o, const Op& p) { return o.k == p.k; })) return "unexplained";
    bool refs = all_ops([](const Op& o, const Op& p) { return o == p || o.k == Op::SYM || o.k == Op::MSYM; });
    return refs ? "reference" : "immediate";
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

// suffix automaton of b[blo:bhi] with edge lists in one pool (the root's transitions in a table by symbol);
// first: where the state's first occurrence in b ends. Symbols are small non-negative ints. One alignment calls
// this many times on smaller and smaller ranges: the buffers are kept between calls, and the root's table is
// emptied by moving to a new generation instead of clearing it.
struct Automaton {
  struct Edge { int c, to, next; };
  struct State { int head; int link; size_t len, first; };
  std::vector<State> st;
  std::vector<Edge> edges;
  std::vector<int> root;      // root[c] valid when stamp[c] == gen
  std::vector<unsigned> stamp;
  std::vector<int> root_syms; // the symbols with a root transition, in the order set
  unsigned gen = 0;
  // the other states' transitions by (state, symbol), open addressing: an instruction's successors can be
  // thousands of distinct tokens, too many to search a list for
  std::vector<u64> keys;      // state << 32 | symbol
  std::vector<int> slot_edge;
  std::vector<unsigned> slot_gen;   // a slot is empty unless its generation is gen
  u64 mask = 0;
  void size_table(size_t max_edges) {   // grown only: the first call of an alignment is its largest
    size_t cap = 16;
    while (cap < 2 * max_edges) cap *= 2;
    if (keys.size() >= cap) return;
    keys.resize(cap);
    slot_edge.resize(cap);
    slot_gen.assign(cap, 0);
    mask = cap - 1;
  }
  size_t slot(int v, int c) const {   // the key's slot, or the empty slot where it would go
    u64 key = u64(u32(v)) << 32 | u32(c);
    size_t i = size_t((key * 0x9E3779B97F4A7C15ull) >> 20) & mask;
    while (slot_gen[i] == gen && keys[i] != key) i = (i + 1) & mask;
    return i;
  }
  bool used(size_t i) const { return slot_gen[i] == gen; }
};

LongestMatch longest_match(Automaton& w, const std::vector<int>& a, const std::vector<int>& b, size_t alo, size_t ahi, size_t blo,
                    size_t bhi) {
  auto& st = w.st;
  auto& edges = w.edges;
  size_t nsym = 0;
  for (size_t p = blo; p < bhi; ++p) nsym = std::max(nsym, size_t(b[p]) + 1);
  if (w.root.size() < nsym) { w.root.resize(nsym); w.stamp.resize(nsym, 0); }
  ++w.gen;
  w.root_syms.clear();
  st.clear();
  edges.clear();
  st.reserve(2 * (bhi - blo) + 1);
  edges.reserve(3 * (bhi - blo) + 1);
  w.size_table(3 * (bhi - blo) + 1);   // a suffix automaton of n symbols has at most 3n transitions
  st.push_back({-1, -1, 0, 0});
  auto get = [&](int v, int c) -> int {
    if (v == 0) return size_t(c) < nsym && w.stamp[size_t(c)] == w.gen ? w.root[size_t(c)] : -1;
    size_t i = w.slot(v, c);
    return w.used(i) ? edges[size_t(w.slot_edge[i])].to : -1;
  };
  auto set = [&](int v, int c, int to) {
    if (v == 0) {
      if (w.stamp[size_t(c)] != w.gen) { w.stamp[size_t(c)] = w.gen; w.root_syms.push_back(c); }
      w.root[size_t(c)] = to;
      return;
    }
    size_t i = w.slot(v, c);
    if (w.used(i)) { edges[size_t(w.slot_edge[i])].to = to; return; }
    edges.push_back({c, to, st[size_t(v)].head});
    st[size_t(v)].head = int(edges.size() - 1);
    w.keys[i] = u64(u32(v)) << 32 | u32(c);
    w.slot_edge[i] = st[size_t(v)].head;
    w.slot_gen[i] = w.gen;
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
          std::vector<int> syms(w.root_syms);
          std::sort(syms.begin(), syms.end());
          for (int k : syms) set(clone, k, w.root[size_t(k)]);
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
  Automaton w;
  return longest_match(w, a, b, alo, ahi, blo, bhi);
}

std::vector<Opcode> get_opcodes(const std::vector<int>& a, const std::vector<int>& b) {
  size_t la = a.size(), lb = b.size();
  std::vector<std::tuple<size_t, size_t, size_t, size_t>> queue{{0, la, 0, lb}};
  std::vector<LongestMatch> blocks;
  Automaton w;
  while (!queue.empty()) {
    auto [alo, ahi, blo, bhi] = queue.back();
    queue.pop_back();
    LongestMatch x = longest_match(w, a, b, alo, ahi, blo, bhi);
    if (x.k) {
      blocks.push_back(x);
      if (alo < x.i && blo < x.j) queue.emplace_back(alo, x.i, blo, x.j);
      if (x.i + x.k < ahi && x.j + x.k < bhi) queue.emplace_back(x.i + x.k, ahi, x.j + x.k, bhi);
    }
  }
  std::sort(blocks.begin(), blocks.end(), [](const LongestMatch& p, const LongestMatch& q) {
    return std::tie(p.i, p.j, p.k) < std::tie(q.i, q.j, q.k);
  });
  std::vector<LongestMatch> na;
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
                                   const NameMap& names, int context, size_t limit) {
  auto index = [](const std::vector<Insn>& insns) {
    std::unordered_map<i64, size_t> m;
    for (size_t k = 0; k < insns.size(); ++k) m[i64(insns[k].address - insns[0].address)] = k;
    return m;
  };
  auto o_at = index(oi), r_at = index(ri);
  // tokens as small ints (equal exactly when the tokens are), branch targets inside the function left open ("rel",)
  struct WildHash {
    size_t operator()(const Tok* t) const {
      size_t h = std::hash<const void*>()(&t->mnemonic.str());
      auto mix = [&](size_t x) { h ^= x + 0x9e3779b97f4a7c15ull + (h << 6) + (h >> 2); };
      for (auto& o : t->ops) {
        mix(o.k);
        if (o.k == Op::REL) continue;
        mix(size_t(o.base) << 32 | size_t(o.index) << 16 | o.seg);
        mix(std::hash<std::string_view>()(o.bytes));
        mix(std::hash<std::string_view>()(o.key.name));
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
  // the text of an entry is made only for the lines kept: tok is ot[tok] for ' ' and '-', rt[tok] for '+'
  struct Entry { char mark; size_t tok, at; };
  std::vector<Entry> entries;
  for (auto& o : ops) {
    if (o.tag == 'e') {
      for (size_t i = o.i1, j = o.j1; i < o.i2; ++i, ++j) {
        if (same_targets(i, j)) {
          entries.push_back({' ', i, i});
        } else {
          entries.push_back({'-', i, i});
          entries.push_back({'+', j, i});
        }
      }
    } else {
      for (size_t i = o.i1; i < o.i2; ++i) entries.push_back({'-', i, i});
      for (size_t j = o.j1; j < o.j2; ++j) entries.push_back({'+', j, o.i1});
    }
  }
  std::vector<bool> keep(entries.size());
  for (size_t c = 0; c < entries.size(); ++c) {
    if (entries[c].mark == ' ') continue;
    size_t lo = c >= size_t(context) ? c - size_t(context) : 0, hi = std::min(entries.size(), c + size_t(context) + 1);
    for (size_t k = lo; k < hi; ++k) keep[k] = true;
  }
  // lines past the limit are only counted
  std::vector<std::string> out;
  size_t lines = 0;
  long prev = -2;
  for (size_t k = 0; k < entries.size(); ++k) {
    if (!keep[k]) continue;
    const Entry& e = entries[k];
    if (long(k) != prev + 1 && lines++ < limit) out.push_back("@" + std::to_string(e.at));
    if (lines++ < limit) out.push_back(std::string(1, e.mark) + " " + tok_text(e.mark == '+' ? rt[e.tok] : ot[e.tok], names));
    prev = long(k);
  }
  if (lines > limit) out.push_back("... " + std::to_string(lines - limit) + " more lines");
  return out;
}

}  // namespace verifier
