#include "report.hpp"

#include <algorithm>
#include <climits>
#include <optional>
#include <unordered_map>

#include "align.hpp"

namespace verifier {

namespace {

const char* size_name(int n) {
  switch (n) {
    case 1:
      return "byte";
    case 2:
      return "word";
    case 4:
      return "dword";
    case 8:
      return "qword";
    case 16:
      return "xmmword";
    default:
      return "";
  }
}

// An instruction of `c` as a token: its operands decoded again, and what each address operand is taken from the
// address fields the decoding found (Code::add_fields), so what is an address, a branch out of the function or a
// switch table is decided in one place.
void symbolise_into(Tok& tok, const Code& c, const Lean& l, const std::function<Key(u64)>& resolve0,
                    bool const_by_value) {
  const Image& img = *c.img;
  Insn ins = c.insn(l);
  auto fields = c.fields(l);
  auto field = [&](FieldKind kind) -> const Field* {
    for (auto& f : fields)
      if (f.kind == kind) return &f;
    return nullptr;
  };
  auto resolve = [&](u64 t) {
    auto it = img.imports.find(t);
    if (it != img.imports.end()) {
      Key k;
      k.kind = Key::IMP;
      k.imp = &it->second;
      return k;
    }
    return resolve0(t);
  };
  tok.mnemonic = ins.mnemonic;
  for (auto& op : ins.ops) {
    Op o{};
    const Field* f = nullptr;
    if (op.type == OP_REG) {
      o.k = Op::R;
      o.base = reg_canon(op.reg);
    } else if (op.type == OP_IMM) {
      if (!ins.branches()) {
        o.k = Op::I;
        o.v = op.imm();
      } else if ((f = field(F_EXT)) && f->value == op.imm()) {  // a branch out of the function
        o.k = Op::SYM;
        o.key = resolve(u64(f->value));
      } else {
        o.k = Op::REL;
        o.v = op.imm() - i64(c.start);
      }
    } else if (op.type == OP_MEM) {
      if (op.base() == reg_rip() && (f = field(F_RIP))) {
        u64 t = u64(f->value);
        Key r = resolve(t);
        if (const_by_value && r.kind == Key::CONST) {
          o.k = Op::CONST;
          o.key.name = img.bytes(t, op.size ? op.size : 4);
        } else {
          o.k = Op::MSYM;
          o.key = r;
          o.size = op.size;
        }
      } else {
        f = op.index ? field(F_TBL) : nullptr;  // a switch table: by its offset in the function
        o.k = f ? Op::TBL : Op::M;
        o.base = reg_canon(op.base());
        o.index = reg_canon(op.index);
        o.scale = op.scale;
        o.v = f ? f->value : op.disp();
        o.size = op.size;
        if (!f) o.seg = reg_canon(segment_reg(op));
      }
    } else {
      continue;
    }
    tok.ops.push_back(o);
  }
}

}  // namespace

Tok symbolise_one(const Code& c, const Lean& l, const std::function<Key(u64)>& resolve, bool const_by_value) {
  Tok tok;
  symbolise_into(tok, c, l, resolve, const_by_value);
  return tok;
}

Toks symbolise(const Code& c, const std::function<Key(u64)>& resolve, bool const_by_value) {
  Toks toks(c.insns.size());
  for (size_t k = 0; k < c.insns.size(); ++k) symbolise_into(toks[k], c, c.insns[k], resolve, const_by_value);
  return toks;
}

std::string tok_text(const Tok& tok, const NameOf& names) {
  std::string out = tok.mnemonic.str();
  auto target = [&](const Key& r) {
    if (r.kind == Key::VA) {
      std::string_view n = names(r.va);
      out += n.empty() ? hex(r.va) : std::string(n);
    } else {
      out += r.kind == Key::IMP ? imp_str(r.imp) : r.name;
    }
  };
  auto size_of = [&](int size) {  // a memory operand's size: "dword [x]", or "[x]" when the size has no name
    const char* n = size_name(size);
    if (*n) {
      out += n;
      out += ' ';
    }
  };
  for (size_t i = 0; i < tok.ops.size(); ++i) {
    const Op& op = tok.ops[i];
    out += i ? ", " : " ";
    switch (op.k) {
      case Op::R:
        out += reg_name(op.base);
        break;
      case Op::I:
        out += hex_signed(op.v);
        break;
      case Op::REL:
        out += "<+" + hex_signed(op.v) + ">";
        break;  // an offset into the function
      case Op::SYM:
        target(op.key);
        break;
      case Op::MSYM:
        size_of(op.size);
        out += '[';
        target(op.key);
        out += ']';
        break;
      case Op::CONST:
        out += "[const ";
        out += hex_bytes(op.bytes().substr(0, 8));
        out += ']';
        break;
      case Op::TBL:
        size_of(op.size);
        out += "[table+" + hex_signed(op.v) + " + " + reg_name(op.index) + "*" + std::to_string(op.scale) + "]";
        break;
      case Op::M: {
        size_of(op.size);
        if (op.seg) {
          out += reg_name(op.seg);
          out += ':';
        }
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

Category classify(const Toks& a, const Toks& b) {
  auto ncalls = [](const Toks& ts) {
    size_t n = 0;
    for (auto& t : ts) n += t.mnemonic == "call" || (t.mnemonic == "jmp" && !t.ops.empty() && t.ops[0].k == Op::SYM);
    return n;
  };
  if (ncalls(a) != ncalls(b)) return Category::Inlining;
  auto same_mnemonic = [](const Tok& x, const Tok& y) { return x.mnemonic == y.mnemonic; };
  if (std::equal(a.begin(), a.end(), b.begin(), b.end(), same_mnemonic)) {
    size_t n = std::min(a.size(), b.size());
    auto all_ops = [&](auto same) {  // every instruction has as many operands, each pair `same`
      for (size_t i = 0; i < n; ++i) {
        auto &x = a[i].ops, &y = b[i].ops;
        if (x.size() != y.size()) return false;
        for (size_t k = 0; k < x.size(); ++k)
          if (!same(x[k], y[k])) return false;
      }
      return true;
    };
    if (all_ops([](const Op& o, const Op& p) {
          return o == p || (o.k == Op::R && p.k == Op::R) ||
                 (o.k == Op::M && p.k == Op::M && o.scale == p.scale && o.v == p.v && o.size == p.size &&
                  o.seg == p.seg);
        }))
      return Category::Regalloc;
    if (!all_ops([](const Op& o, const Op& p) { return o.k == p.k; })) return Category::Unexplained;
    bool refs = all_ops([](const Op& o, const Op& p) { return o == p || o.k == Op::SYM || o.k == Op::MSYM; });
    return refs ? Category::Reference : Category::Immediate;
  }
  if (a.size() == b.size()) {  // the same mnemonics in another order (counted: a mnemonic is one interned string)
    std::vector<int> count(Mnem::count());
    for (auto& t : a) ++count[t.mnemonic.id()];
    for (auto& t : b) --count[t.mnemonic.id()];
    if (std::all_of(count.begin(), count.end(), [](int c) { return c == 0; })) return Category::Reorder;
  }
  long d = long(a.size()) - long(b.size());
  if (std::labs(d) > std::max<long>(4, long(a.size()) / 4)) return Category::Inlining;
  return Category::Unexplained;
}

// the original's RIP-relative operand stands for its bytes where the rebuilt one is a compiler constant (by value)
void const_by_value(Tok& o, const Tok& r, const Image& O) {
  if (r.ops.size() != o.ops.size()) return;
  for (size_t z = 0; z < r.ops.size(); ++z) {
    if (r.ops[z].k == Op::CONST && o.ops[z].k == Op::MSYM) {
      Op c{};
      c.k = Op::CONST;
      c.key.name = O.bytes(o.ops[z].key.va, i64(r.ops[z].bytes().size()));
      o.ops[z] = c;
    }
  }
}

std::optional<Category> classify_mnemonics(const Code& a, const Code& b) {
  if (std::equal(a.insns.begin(), a.insns.end(), b.insns.begin(), b.insns.end(),
                 [](const Lean& x, const Lean& y) { return x.mnem == y.mnem; }))
    return std::nullopt;
  static const u16 call = Mnem("call").id(), jmp = Mnem("jmp").id();
  auto ncalls = [](const Code& c) {  // calls, and jumps out of the function (tail calls)
    size_t n = 0;
    for (auto& l : c.insns) {
      auto fs = c.fields(l);
      n += l.mnem == call ||
           (l.mnem == jmp && std::any_of(fs.begin(), fs.end(), [](const Field& f) { return f.kind == F_EXT; }));
    }
    return n;
  };
  if (ncalls(a) != ncalls(b)) return Category::Inlining;
  if (a.insns.size() == b.insns.size()) {  // the same mnemonics in another order
    std::vector<int> count(Mnem::count());
    for (auto& l : a.insns) ++count[l.mnem];
    for (auto& l : b.insns) --count[l.mnem];
    if (std::all_of(count.begin(), count.end(), [](int c) { return c == 0; })) return Category::Reorder;
  }
  long d = long(a.insns.size()) - long(b.insns.size());
  if (std::labs(d) > std::max<long>(4, long(a.insns.size()) / 4)) return Category::Inlining;
  return Category::Unexplained;
}

namespace {

// a relative branch's offset in its bytes (after the prefixes: E8/E9 and 0F 8x take 4 bytes, EB, 7x and E0-E3 one;
// it ends the instruction), {0, 0} for any other instruction
std::pair<u8, u8> rel_operand(std::string_view b) {
  size_t p = 0;
  while (p < b.size() && (b[p] == '\x66' || b[p] == '\xf2' || b[p] == '\xf3' || b[p] == '\x2e' || b[p] == '\x3e' ||
                          (u8(b[p]) & 0xf0) == 0x40))
    ++p;
  if (p >= b.size()) return {0, 0};
  u8 op = u8(b[p]);
  u8 size = op == 0xe8 || op == 0xe9                                                 ? 4
            : op == 0xeb || (op >= 0x70 && op <= 0x7f) || (op >= 0xe0 && op <= 0xe3) ? 1
            : op == 0x0f && p + 1 < b.size() && (u8(b[p + 1]) & 0xf0) == 0x80        ? 4
                                                                                     : 0;
  if (!size || b.size() < size) return {0, 0};
  return {u8(b.size() - size), size};
}

constexpr size_t NONE_AT = ~size_t(0);

// where an instruction has a REX prefix without bits (40) right before its opcode, NONE_AT when it has none
size_t empty_rex(std::string_view b) {
  auto legacy = [](u8 c) {  // a legacy prefix: operand or address size, lock, rep, segment
    return c == 0x66 || c == 0x67 || c == 0xf0 || c == 0xf2 || c == 0xf3 || c == 0x2e || c == 0x3e || c == 0x26 ||
           c == 0x36 || c == 0x64 || c == 0x65;
  };
  size_t p = 0;
  while (p < b.size() && legacy(u8(b[p]))) ++p;
  return p + 1 < b.size() && u8(b[p]) == 0x40 ? p : NONE_AT;
}

i64 read_signed(std::string_view b, size_t at, size_t n) {
  u64 raw = 0;
  for (size_t i = 0; i < n; ++i) raw |= u64(u8(b[at + i])) << (8 * i);
  return n < 8 && (raw >> (8 * n - 1) & 1) ? i64(raw | (~u64(0) << (8 * n))) : i64(raw);
}

constexpr i64 NO_TARGET = INT64_MIN;

// Each instruction of both functions as a small int, equal exactly when the comparison would take the two as the same
// instruction: the same bytes outside the address fields and the branch offset inside the function, the fields at the
// same places, and each field standing for the same thing. A rebuilt address stands for the original one its name
// resolves to, or else for one of the original function's own targets that the matching holds, or whose bytes are
// the same literal's; nothing here guesses a new pair (Comparer::ref may, so it is not called). Branches inside the
// function are left open: whether they agree depends on the alignment (CodeDiff::same_targets).
class Identities {
 public:
  Identities(const Code& oc, const Code& rc, const DiffContext& cx) : oc_(oc), rc_(rc), cx_(cx) {}
  // What the diff reads of each of the rebuilt function's fields, in order, given the original function: what its name
  // resolves to, and a literal's bytes (what it stands for follows from them and the original's bytes) or else what
  // it stands for.
  std::string rebuilt_targets() {
    key_.clear();
    for (auto& f : rc_.field_list) {
      u64 t = u64(f.value);
      if (f.kind == F_TBL || t == rc_.img->base || rc_.img->imports.count(t)) {
        target_key(true, f);
        continue;
      }
      Key k = cx_.resolve(t);
      put64(char('a' + k.kind), k.va);
      key_ += k.name;
      key_ += '\0';
      if (k.kind == Key::VA) continue;
      if (Bytes s = literal(k, t, f.access); !s.empty()) {
        key_ += s;
        key_ += '\0';
        if (k.kind == Key::CONST) key_ += rc_.img->bytes(t, 32);  // a token shows as many as its operand reads
      } else {
        target_key(true, f);
      }
    }
    return key_;
  }
  // ids, and per instruction the in-function branch target (function-relative, NO_TARGET for none)
  void side(bool rebuilt, std::vector<u32>& ids, std::vector<i64>& rel) {
    const Code& c = rebuilt ? rc_ : oc_;
    if (slots_.empty()) {
      size_t cap = 16;
      while (cap < 2 * (oc_.insns.size() + rc_.insns.size())) cap *= 2;
      slots_.assign(cap, Slot{});
    }
    ids.reserve(c.insns.size());
    rel.reserve(c.insns.size());
    for (auto& l : c.insns) {
      auto fs = c.fields(l);
      // the bytes with the fields and an in-function branch offset zeroed, then the fields' places
      std::string_view b = c.bytes(l);
      key_.assign(b);
      for (auto& f : fs) std::fill_n(key_.begin() + f.off, std::min<size_t>(f.size, key_.size() - f.off), '\0');
      i64 target = NO_TARGET;
      bool ext = std::any_of(fs.begin(), fs.end(), [](const Field& f) { return f.kind == F_EXT; });
      auto [at, n] = rel_operand(b);
      if (n && !ext) {
        target = i64(l.off) + i64(l.size) + read_signed(b, at, n);
        std::fill_n(key_.begin() + at, n, '\0');
      }
      // a REX prefix that changes nothing (40) is an encoding difference only: aligned, then shown as one
      size_t rex = empty_rex(b);
      if (rex != NONE_AT) key_.erase(rex, 1);
      auto place = [&](size_t off) { return char(rex != NONE_AT && off > rex ? off - 1 : off); };
      for (auto& f : fs) {
        key_ += char(f.kind);
        key_ += place(f.off);
        key_ += char(f.size);
      }
      if (n && !ext) key_ += 'J';
      for (auto& f : fs) target_key(rebuilt, f);
      ids.push_back(id_of(key_));
      rel.push_back(target);
    }
  }

 private:
  const Code &oc_, &rc_;
  const DiffContext& cx_;
  std::vector<u64> targets_;
  bool targets_made_ = false;
  // the keys seen, as ids in order of first sight: open addressing over their hashes, the keys in one buffer
  struct Slot {
    size_t hash = 0;
    u32 at = 0, size = 0, id = 0;  // id 0: empty (ids are numbered from 1)
  };
  std::vector<Slot> slots_;
  std::string keys_;
  u32 next_id_ = 0;
  u32 id_of(std::string_view key) {
    size_t h = std::hash<std::string_view>()(key), mask = slots_.size() - 1;
    for (size_t i = h & mask;; i = (i + 1) & mask) {
      Slot& s = slots_[i];
      if (!s.id) {
        s = {h, u32(keys_.size()), u32(key.size()), ++next_id_};
        keys_ += key;
        return s.id;
      }
      if (s.hash == h && std::string_view(keys_).substr(s.at, s.size) == key) return s.id;
    }
  }
  std::unordered_map<u64, std::optional<u64>> stands_for_;
  std::string key_;

  void put64(char tag, u64 v) {
    key_ += tag;
    key_.append(reinterpret_cast<const char*>(&v), 8);
  }
  void target_key(bool rebuilt, const Field& f) {
    const Image& img = rebuilt ? *rc_.img : *oc_.img;
    u64 t = u64(f.value);
    if (f.kind == F_TBL) return put64('T', t);
    if (t == img.base) return put64('B', 0);
    if (auto it = img.imports.find(t); it != img.imports.end()) {
      key_ += 'I';
      key_ += it->second.dll;
      key_ += '\0';
      key_ += it->second.name;
      key_ += '\0';
      key_.append(reinterpret_cast<const char*>(&it->second.ordinal), 4);
      return;
    }
    if (!rebuilt) return put64('V', t);
    auto it = stands_for_.find(t);
    if (it == stands_for_.end()) it = stands_for_.emplace(t, stands_for(t, f.access)).first;
    if (it->second) return put64('V', *it->second);
    put64('U', t);  // stands for nothing the original has here
  }
  // a literal's bytes, as the original's are compared with them (empty: not a literal)
  Bytes literal(const Key& k, u64 r, int access) const {
    if (k.kind == Key::STR) return rc_.img->cstring(r, k.wide());
    if (k.kind != Key::CONST) return {};
    i64 n = constant_size(k.name);
    return Bytes(rc_.img->bytes(r, n ? n : access ? access : 4));
  }
  // the original's targets other than imports and __ImageBase, sorted (made when first needed)
  const std::vector<u64>& targets() {
    if (!targets_made_) {
      for (auto& f : oc_.field_list)
        if (f.kind != F_TBL && !oc_.img->imports.count(u64(f.value)) && u64(f.value) != oc_.img->base)
          targets_.push_back(u64(f.value));
      std::sort(targets_.begin(), targets_.end());
      targets_.erase(std::unique(targets_.begin(), targets_.end()), targets_.end());
      targets_made_ = true;
    }
    return targets_;
  }
  std::optional<u64> stands_for(u64 r, int access) {
    const Image& O = *oc_.img;
    Key k = cx_.resolve(r);
    if (k.kind == Key::VA) return k.va;
    Bytes s = literal(k, r, access);
    using MK = Matching::Kind;
    for (u64 o : targets()) {
      if (!s.empty()) {
        if (!O.writable(o) && O.bytes(o, i64(s.size())) == s) return o;
      } else if (cx_.matching && (cx_.matching->holds(MK::Function, o, r) || cx_.matching->holds(MK::Data, o, r) ||
                                  cx_.matching->holds(MK::Vtable, o, r))) {
        return o;
      }
    }
    return std::nullopt;
  }
};

}  // namespace

std::string rebuilt_targets(const Code& oc, const Code& rc, const DiffContext& cx) {
  return Identities(oc, rc, cx).rebuilt_targets();
}

CodeDiff code_diff(const Code& oc, const Code& rc, const DiffContext& cx, bool want_lines, int context, size_t limit) {
  std::vector<u32> ia, ib;
  std::vector<i64> ra, rb;
  {
    Identities ids(oc, rc, cx);
    ids.side(false, ia, ra);
    ids.side(true, ib, rb);
  }
  auto ops = align(ia, ib);
  constexpr size_t NONE = ~size_t(0);
  // the original's instruction -> the rebuilt one in its place: aligned with it, or at the same place in a block
  // replaced by as many instructions (registers allocated otherwise, say)
  std::vector<size_t> aligned(ia.size(), NONE);
  for (auto& o : ops)
    if (o.tag == 'e' || (o.tag == 'r' && o.i2 - o.i1 == o.j2 - o.j1))
      for (size_t i = o.i1, j = o.j1; i < o.i2 && j < o.j2; ++i, ++j) aligned[i] = j;
  // the instruction at a function-relative offset, if one starts there
  auto at = [](const Code& c, i64 v) -> size_t {
    auto it = std::lower_bound(c.insns.begin(), c.insns.end(), v, [](const Lean& l, i64 x) { return i64(l.off) < x; });
    return it != c.insns.end() && i64(it->off) == v ? size_t(it - c.insns.begin()) : NONE;
  };
  // an aligned pair's branches inside the function go to instructions in each other's place
  auto same_targets = [&](size_t i, size_t j) {
    if (ra[i] == NO_TARGET) return true;
    size_t ti = at(oc, ra[i]), tj = at(rc, rb[j]);
    return (ti == NONE ? NONE : aligned[ti]) == tj;
  };
  // a line: '-' and ' ' show the original's instruction i, '+' the rebuilt one j; `at` is the original's index where it
  // is; `other`: the instruction on the other side it pairs with (NONE: none)
  struct Entry {
    char mark;
    size_t i, j, at, other;
  };
  std::vector<Entry> entries;
  CodeDiff out;
  for (auto& o : ops) {
    if (o.tag == 'e') {
      for (size_t i = o.i1, j = o.j1; i < o.i2; ++i, ++j) {
        if (same_targets(i, j) && oc.insns[i].size == rc.insns[j].size) {
          entries.push_back({' ', i, j, i, NONE});
        } else {
          entries.push_back({'-', i, j, i, j});
          entries.push_back({'+', i, j, i, i});
        }
      }
    } else {
      size_t pairs = std::min(o.i2 - o.i1, o.j2 - o.j1);  // a replaced block pairs its instructions in order
      for (size_t i = o.i1; i < o.i2; ++i)
        entries.push_back({'-', i, o.j1, i, i - o.i1 < pairs ? o.j1 + i - o.i1 : NONE});
      for (size_t j = o.j1; j < o.j2; ++j)
        entries.push_back({'+', o.i2, j, o.i1, j - o.j1 < pairs ? o.i1 + j - o.j1 : NONE});
    }
  }
  for (auto& e : entries) {
    if (e.mark == ' ') continue;
    out.differs = true;
    // where the first difference is: the original's instruction there and the rebuilt one in its place
    size_t i = e.mark == '-' ? e.i : e.at, j = e.j;
    if (i < oc.insns.size() && j < rc.insns.size()) out.first = {i, j};
    break;
  }
  if (!want_lines || !out.differs) return out;
  std::vector<bool> keep(entries.size());
  for (size_t c = 0; c < entries.size(); ++c) {
    if (entries[c].mark == ' ') continue;
    size_t lo = c >= size_t(context) ? c - size_t(context) : 0, hi = std::min(entries.size(), c + size_t(context) + 1);
    for (size_t k = lo; k < hi; ++k) keep[k] = true;
  }
  // the text of an instruction, made only for the lines shown (each at most once: a pair's lines are shown together)
  static const std::function<Key(u64)> by_va = [](u64 t) { return Key::of_va(t); };
  std::unordered_map<size_t, Tok> rtoks;
  std::unordered_map<size_t, std::string> otexts, rtexts;
  auto rtok = [&](size_t j) -> const Tok& {
    auto it = rtoks.find(j);
    if (it == rtoks.end()) it = rtoks.emplace(j, symbolise_one(rc, rc.insns[j], cx.resolve, true)).first;
    return it->second;
  };
  auto rtext = [&](size_t j) -> const std::string& {
    auto it = rtexts.find(j);
    if (it == rtexts.end()) it = rtexts.emplace(j, tok_text(rtok(j), cx.names)).first;
    return it->second;
  };
  auto otext = [&](size_t i, size_t other) -> const std::string& {  // `other`: the rebuilt one it pairs with
    auto it = otexts.find(i);
    if (it == otexts.end()) {
      Tok o = symbolise_one(oc, oc.insns[i], by_va, false);
      if (other != NONE) const_by_value(o, rtok(other), *oc.img);
      it = otexts.emplace(i, tok_text(o, cx.names)).first;
    }
    return it->second;
  };
  auto text = [&](const Entry& e) -> const std::string& { return e.mark == '+' ? rtext(e.j) : otext(e.i, e.other); };
  // A pair that reads the same: two branches inside the function to the same offset whose targets are not in each
  // other's place (their lines say so), or else a difference in encoding only (their lines give the bytes).
  auto same_text = [&](const Entry& e) {
    if (e.mark == ' ' || e.other == NONE) return std::string();
    size_t i = e.mark == '-' ? e.i : e.other, j = e.mark == '+' ? e.j : e.other;
    std::string_view x = oc.bytes(oc.insns[i]), y = rc.bytes(rc.insns[j]);
    if (oc.insns[i].mnem != rc.insns[j].mnem || otext(i, j) != rtext(j)) return std::string();
    if (ra[i] != NO_TARGET && rb[j] != NO_TARGET && x.size() == y.size()) return std::string("  ; target not aligned");
    if (x == y) return std::string();
    return "  ; encoding " + hex_bytes(e.mark == '-' ? x : y);
  };
  // lines past the limit are only counted
  size_t lines = 0;
  long prev = -2;
  for (size_t k = 0; k < entries.size(); ++k) {
    if (!keep[k]) continue;
    const Entry& e = entries[k];
    if (long(k) != prev + 1 && lines++ < limit) out.lines.push_back("@" + std::to_string(e.at));
    if (lines++ < limit) out.lines.push_back(std::string(1, e.mark) + " " + text(e) + same_text(e));
    prev = long(k);
  }
  if (lines > limit) out.lines.push_back("... " + std::to_string(lines - limit) + " more lines");
  return out;
}

}  // namespace verifier
