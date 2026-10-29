#include "x64.hpp"

#include <capstone/capstone.h>

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <unordered_map>

namespace verifier {

namespace {

// The capstone handle, detail on.
struct Decoder {
  csh h = 0;
  Decoder() {
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &h) != CS_ERR_OK) throw std::runtime_error("capstone: cs_open failed");
    cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
  }
  ~Decoder() { cs_close(&h); }
};
Decoder& decoder() {
  static Decoder d;
  return d;
}

u8 group_bit(u8 g) { return g == GRP_JUMP ? 1 : g == GRP_CALL ? 2 : g == GRP_BRANCH_RELATIVE ? 4 : 0; }
std::vector<int>& gpr_table();

Insn copy_insn(csh h, const cs_insn* i) {
  Insn r;
  r.address = i->address;
  r.size = static_cast<u8>(i->size);
  r.mnemonic = Mnem(i->mnemonic);
  std::memcpy(r.raw, i->bytes, std::min<size_t>(i->size, 15));
  const cs_detail* d = i->detail;
  const cs_x86& x = d->x86;
  for (int k = 0; k < x.op_count; ++k) {
    const cs_x86_op& o = x.operands[k];
    Operand op;
    op.type = static_cast<u8>(o.type);
    op.size = o.size;
    if (o.type == X86_OP_IMM) op.imm = o.imm;
    else if (o.type == X86_OP_REG) op.reg = static_cast<u16>(o.reg);
    else if (o.type == X86_OP_MEM) {
      op.mem = Mem{};
      op.mem.base = static_cast<u16>(o.mem.base);
      op.mem.index = static_cast<u16>(o.mem.index);
      op.mem.scale = static_cast<i8>(o.mem.scale);
      op.mem.disp = o.mem.disp;
      op.mem.segment = static_cast<u16>(o.mem.segment);
    }
    r.ops.push_back(op);
  }
  for (int k = 0; k < d->groups_count; ++k) r.gmask |= group_bit(d->groups[k]);
  cs_regs rr, ww;
  uint8_t nr = 0, nw = 0;
  if (cs_regs_access(h, i, rr, &nr, ww, &nw) == CS_ERR_OK) {
    auto& t = gpr_table();
    for (int k = 0; k < nw; ++k) if (ww[k] < t.size() && t[ww[k]] >= 0) r.wmask |= u16(1u << t[ww[k]]);
  }
  r.imm_offset = x.encoding.imm_offset;
  r.imm_size = x.encoding.imm_size;
  r.disp_offset = x.encoding.disp_offset;
  r.disp_size = x.encoding.disp_size;
  return r;
}

std::vector<int>& gpr_table() {
  static std::vector<int> t;
  if (t.empty()) {
    static const std::unordered_map<std::string, int> names = [] {
      std::unordered_map<std::string, int> m;
      const char* abcd[] = {"a", "b", "c", "d"};
      for (int k = 0; k < 4; ++k) {
        std::string x = abcd[k];
        for (auto n : {"r" + x + "x", "e" + x + "x", x + "x", x + "l", x + "h"}) m[n] = k;
      }
      const char* sidi[] = {"si", "di", "bp", "sp"};
      for (int k = 0; k < 4; ++k) {
        std::string x = sidi[k];
        for (auto n : {"r" + x, "e" + x, x, x + "l"}) m[n] = 4 + k;
      }
      for (int k = 8; k < 16; ++k) {
        std::string x = "r" + std::to_string(k);
        for (auto n : {x, x + "d", x + "w", x + "b"}) m[n] = k;
      }
      return m;
    }();
    t.assign(X86_REG_ENDING, -1);
    for (int r = 1; r < X86_REG_ENDING; ++r) {
      const char* n = cs_reg_name(decoder().h, r);
      if (!n) continue;
      auto it = names.find(n);
      if (it != names.end()) t[r] = it->second;
    }
  }
  return t;
}

// rax rcx rdx r8 r9 r10 r11 in the GPR numbering above (a=0 b=1 c=2 d=3 si=4 di=5 bp=6 sp=7 r8..r15)
constexpr u32 VOLATILE = (1u << 0) | (1u << 2) | (1u << 3) | (1u << 8) | (1u << 9) | (1u << 10) | (1u << 11);

}  // namespace

const std::string& Mnem::intern(std::string_view s) {
  static std::unordered_map<std::string, std::unique_ptr<std::string>> table;
  auto it = table.find(std::string(s));
  if (it == table.end()) it = table.emplace(std::string(s), std::make_unique<std::string>(s)).first;
  return *it->second;
}

bool Insn::group(u8 g) const { return (gmask & group_bit(g)) != 0; }
bool Insn::branches() const { return (gmask & 7) != 0; }

std::string Insn::op_str() const {
  Decoder& d = decoder();
  cs_insn* insn = nullptr;
  std::string s;
  if (cs_disasm(d.h, reinterpret_cast<const uint8_t*>(raw), size, address, 1, &insn) == 1) s = insn->op_str;
  if (insn) cs_free(insn, 1);
  return s;
}

const char* reg_name(u16 reg) {
  const char* n = reg ? cs_reg_name(decoder().h, reg) : nullptr;
  return n ? n : "";
}
u16 reg_rip() { return X86_REG_RIP; }
int gpr_index(u16 reg) { auto& t = gpr_table(); return reg < t.size() ? t[reg] : -1; }

const char* field_kind_name(FieldKind k) {
  switch (k) {
    case F_ABS: return "abs";
    case F_EXT: return "ext";
    case F_IMG: return "img";
    case F_RIP: return "rip";
    case F_TBL: return "tbl";
  }
  return "?";
}

bool Field::operator<(const Field& o) const {
  if (off != o.off) return off < o.off;
  if (size != o.size) return size < o.size;
  if (kind != o.kind) return kind < o.kind;
  if (value != o.value) return value < o.value;
  return access < o.access;
}

std::vector<Insn> decode_linear(std::string_view code, u64 start) {
  Decoder& d = decoder();
  std::vector<Insn> out;
  cs_insn* insn = cs_malloc(d.h);
  const uint8_t* p = reinterpret_cast<const uint8_t*>(code.data());
  size_t n = code.size();
  uint64_t addr = start;
  while (n && cs_disasm_iter(d.h, &p, &n, &addr, insn)) out.push_back(copy_insn(d.h, insn));
  cs_free(insn, 1);
  return out;
}

Code::Code(const Image& im, u64 s, u64 e) : img(&im), start(s), end(e) {
  code = Bytes(im.bytes(s, i64(e) - i64(s)));
  relocated = im.reloc_lower_bound(e) > im.reloc_lower_bound(s);
  i64 frva = i64(s - im.base), erva = i64(e - im.base);
  i64 n = i64(code.size());
  cut = n;
  u16 rip = X86_REG_RIP;
  {
    Decoder& d = decoder();
    cs_insn* insn = cs_malloc(d.h);
    const uint8_t* p = reinterpret_cast<const uint8_t*>(code.data());
    size_t left = code.size();
    uint64_t addr = s;
    while (left && cs_disasm_iter(d.h, &p, &left, &addr, insn)) {
      i64 k = i64(insn->address - s);
      if (k >= cut) break;
      Insn ins = copy_insn(d.h, insn);
      for (auto& op : ins.ops) {
        if (op.type == OP_MEM && op.mem.base != rip && op.mem.index && frva <= op.mem.disp &&
            op.mem.disp < erva + i64(TABLE_SLACK)) {
          i64 t = op.mem.disp - frva;
          auto it = tables.find(t);
          tables[t] = std::max(it == tables.end() ? 0 : it->second, int(op.size));
          if (t < cut) cut = std::max(t, i64(ins.address + ins.size - s));
        }
      }
      insns.push_back(std::move(ins));
    }
    cs_free(insn, 1);
  }
  // alignment nops after the last ret/jmp (before a switch table) are padding, not code
  while (insns.size() > 1 && insns.back().mnemonic == "nop" &&
         (insns[insns.size() - 2].mnemonic == "ret" || insns[insns.size() - 2].mnemonic == "jmp") &&
         i64(insns.back().address + insns.back().size - s) == cut) {
    cut = i64(insns.back().address - s);
    insns.pop_back();
  }
  // a dword table at the cut whose entries point past every in-span table: decoding resumes there
  if (cut < n && tables.count(cut) && tables[cut] == 4) {
    i64 nxt = n;
    for (auto& [t, sz] : tables) if (cut < t && t < n) { nxt = t; break; }
    i64 last = cut;
    for (auto& [t, sz] : tables) if (t < n) last = std::max(last, t);
    std::vector<i64> targets;
    i64 j = cut;
    while (j + 4 <= nxt) {
      i64 tgt = i64(le32(code.data() + j)) - frva;
      if (!(0 <= tgt && tgt < n)) break;
      targets.push_back(tgt);
      j += 4;
    }
    for (i64 t : targets) if (t >= j && t > last && (!resume || t < *resume)) resume = t;
  }
  if (resume) {
    auto more = decode_linear(std::string_view(code).substr(size_t(*resume)), s + u64(*resume));
    for (auto& i : more) insns.push_back(std::move(i));
  }
  i64 decoded = 0;
  for (auto& i : insns) decoded += i.size;
  complete = decoded == cut + (resume ? n - *resume : 0);
  image_base = image_base_regs(insns, im.base);
  insns.shrink_to_fit();   // functions stay decoded for the run: no growth slack
  trim_padding();
}

void Code::trim_padding() {
  i64 n = i64(code.size());
  if (cut < n && !resume) {
    for (auto& [t, sz] : tables) if (t < n) return;
    code.resize(size_t(cut));
  }
}

std::vector<TableItem> Code::table_region() const {
  std::vector<TableItem> out;
  i64 size = i64(code.size()), n = resume ? *resume : size, k = cut;
  i64 frva = i64(start - img->base);
  std::vector<i64> starts;
  for (auto& [t, sz] : tables) if (cut <= t && t < n) starts.push_back(t);
  auto entry = [&](i64 x) { return i64(le32(code.data() + x)) - frva; };
  Bytes raw;
  while (k < n) {
    auto it = tables.find(k);
    if (it != tables.end() && it->second == 4) {
      i64 nxt = n;
      for (i64 t : starts) if (t > k) { nxt = t; break; }
      i64 j = k;
      while (j + 4 <= nxt && 0 <= entry(j) && entry(j) < size) j += 4;
      if (j > k) {
        if (!raw.empty()) { out.push_back({false, 0, raw}); raw.clear(); }
        for (i64 x = k; x < j; x += 4) out.push_back({true, entry(x), {}});
        k = j;
        continue;
      }
    }
    raw += code[size_t(k)];
    ++k;
  }
  if (!raw.empty()) out.push_back({false, 0, raw});
  return out;
}

std::vector<OutsideTable> Code::outside_tables() const {
  i64 n = i64(code.size());
  std::vector<i64> starts;
  for (auto& [t, sz] : tables) if (t >= n) starts.push_back(t);
  std::vector<OutsideTable> out;
  for (size_t i = 0; i < starts.size(); ++i) {
    i64 t = starts[i];
    i64 nxt = i + 1 < starts.size() ? starts[i + 1] : t + 4 * 512;
    OutsideTable o{t, false, {}, {}};
    if (tables.at(t) == 4) {
      o.dword = true;
      for (i64 k = t; k < nxt; k += 4) {
        i64 e = i64(img->u32_at(start + u64(k))) - i64(start - img->base);
        if (!(0 <= e && e < n)) break;
        o.entries.push_back(e);
      }
    } else {
      o.raw = Bytes(img->bytes(start + u64(t), std::min<i64>(nxt - t, 256)));
    }
    out.push_back(std::move(o));
  }
  return out;
}

std::vector<Field> Code::fields(const Insn& ins) const {
  std::vector<Field> out;
  i64 frva = i64(start - img->base);
  if (ins.branches()) {
    for (auto& op : ins.ops)
      if (op.type == OP_IMM && !(i64(start) <= op.imm && op.imm < i64(end)) && ins.imm_size)
        out.push_back({ins.imm_offset, ins.imm_size, F_EXT, op.imm, 0});
  }
  for (auto& op : ins.ops) {
    if (op.type != OP_MEM) continue;
    if (op.mem.base == X86_REG_RIP) {
      int size = ins.mnemonic == "lea" ? 0 : op.size;
      out.push_back({ins.disp_offset, 4, F_RIP, i64(ins.address + ins.size) + op.mem.disp, size});
    } else if (op.mem.index && tables.count(op.mem.disp - frva)) {
      out.push_back({ins.disp_offset, ins.disp_size, F_TBL, op.mem.disp - frva, 0});
    } else if (image_relative(ins, op)) {
      out.push_back({ins.disp_offset, ins.disp_size, F_IMG, i64(img->base) + op.mem.disp, op.size});
    }
  }
  if (relocated) {
    size_t i = img->reloc_lower_bound(ins.address);
    while (i < img->reloc_sorted.size() && img->reloc_sorted[i] < ins.address + ins.size) {
      u64 site = img->reloc_sorted[i];
      out.push_back({int(site - ins.address), 8, F_ABS, i64(img->u64_at(site)), 0});
      ++i;
    }
  }
  if (out.size() > 1) std::sort(out.begin(), out.end());
  return out;
}

bool Code::image_relative(const Insn& ins, const Operand& op) const {
  size_t k;
  if (!insns.empty() && &ins >= insns.data() && &ins < insns.data() + insns.size()) {
    k = size_t(&ins - insns.data());
  } else {   // a copy: by address (instructions are in address order)
    auto it = std::lower_bound(insns.begin(), insns.end(), ins.address, [](const Insn& i, u64 a) { return i.address < a; });
    if (it == insns.end() || it->address != ins.address) return false;
    k = size_t(it - insns.begin());
  }
  u32 have = k < image_base.size() ? image_base[k] : 0;
  if (!have) return false;
  u32 regs = 0;
  for (u16 r : {op.mem.base, op.mem.index}) if (r) { int g = gpr_index(r); if (g >= 0) regs |= 1u << g; }
  return (have & regs) && op.mem.disp > 0 && img->flags(img->base + u64(op.mem.disp)).has_value();
}

std::vector<u32> image_base_regs(const std::vector<Insn>& insns, u64 base) {
  // must-analysis over the instructions' control flow: which GPRs hold __ImageBase on entry to each one
  size_t n = insns.size();
  auto index_of = [&](u64 a) -> long {   // instructions are in address order
    auto it = std::lower_bound(insns.begin(), insns.end(), a, [](const Insn& i, u64 x) { return i.address < x; });
    return it != insns.end() && it->address == a ? long(it - insns.begin()) : -1;
  };
  // predecessors as flat arrays (CSR): fall-through from k-1, and jumps with an immediate target
  std::vector<u32> npred(n + 1, 0);
  std::vector<std::pair<u32, u32>> edges;   // (to, from)
  edges.reserve(n + n / 4);
  std::vector<u32> switches;
  auto falls = [](const Insn& ins) {
    const std::string& m = ins.mnemonic;
    return !(m == "jmp" || m == "ud2" || m == "int3" || starts_with(m, "ret"));
  };
  for (size_t k = 0; k < n; ++k) {
    const Insn& ins = insns[k];
    if (k + 1 < n && falls(ins)) edges.emplace_back(u32(k + 1), u32(k));
    if (ins.group(GRP_JUMP) && !ins.ops.empty() && ins.ops[0].type == OP_IMM) {
      long t = index_of(u64(ins.ops[0].imm));
      if (t >= 0) edges.emplace_back(u32(t), u32(k));
    }
    if (ins.mnemonic == "jmp" && !ins.ops.empty() && ins.ops[0].type == OP_REG) switches.push_back(u32(k));
  }
  for (auto& [to, from] : edges) ++npred[to + 1];
  for (size_t k = 0; k < n; ++k) npred[k + 1] += npred[k];
  std::vector<u32> pred(edges.size());
  {
    std::vector<u32> fill(npred.begin(), npred.end() - 1);
    for (auto& [to, from] : edges) pred[fill[to]++] = from;
  }
  // an instruction nothing reaches (after a computed jump) may be any switch's case
  auto preds_of = [&](size_t k, const u32*& b, const u32*& e) {
    if (npred[k] == npred[k + 1] && k >= 1) { b = switches.data(); e = b + switches.size(); }
    else { b = pred.data() + npred[k]; e = pred.data() + npred[k + 1]; }
  };

  std::vector<u32> kill(n), gen(n);
  for (size_t k = 0; k < n; ++k) {
    const Insn& ins = insns[k];
    u32 kl = ins.wmask;
    if (ins.group(GRP_CALL)) kl |= VOLATILE;
    u32 g = 0;
    if (ins.mnemonic == "lea" && ins.ops.size() == 2 && ins.ops[1].type == OP_MEM) {
      const Mem& m = ins.ops[1].mem;
      if (m.base == X86_REG_RIP && !m.index && u64(i64(ins.address + ins.size) + m.disp) == base) {
        int x = gpr_index(ins.ops[0].reg);
        if (x >= 0) g = 1u << x;
      }
    }
    kill[k] = kl; gen[k] = g;
  }
  constexpr u32 TOP = 0xFFFFFFFFu;   // "not reached yet": every register (must-analysis from the top)
  std::vector<u32> state(n);
  std::vector<char> reached(n);
  for (size_t k = 0; k < n; ++k) {
    const u32 *b, *e;
    preds_of(k, b, e);
    reached[k] = k == 0 || b == e;
    state[k] = reached[k] ? 0 : TOP;
  }
  bool changed = true;
  while (changed) {
    changed = false;
    for (size_t k = 1; k < n; ++k) {
      const u32 *b, *e;
      preds_of(k, b, e);
      if (b == e) continue;
      bool any = false;
      u32 nw = TOP;
      for (const u32* p = b; p != e; ++p) {
        if (!reached[*p]) continue;
        nw &= (state[*p] & ~kill[*p]) | gen[*p];
        any = true;
      }
      if (any != bool(reached[k]) || (any && nw != state[k])) {
        reached[k] = any;
        state[k] = any ? nw : TOP;
        changed = true;
      }
    }
  }
  for (size_t k = 0; k < n; ++k) if (!reached[k]) state[k] = 0;
  return state;
}

std::optional<u64> leaf_extent(const Image& img, u64 va) {
  // straight-line decode up to the ret/jmp no earlier internal branch jumps past, in growing slices
  // (a slice ending on a truncated instruction is continued)
  u64 reach = va;
  Bytes window(img.bytes(va, i64(MAX_DATA_COMPARE)));
  size_t at = 0, size = 64;
  for (;;) {
    size_t endp = std::min(at + size, window.size());
    u64 nxt = va + at;
    for (auto& ins : decode_linear(std::string_view(window).substr(at, endp - at), va + at)) {
      nxt = ins.address + ins.size;
      for (auto& op : ins.ops)
        if (op.type == OP_IMM && (ins.group(GRP_JUMP) || ins.group(GRP_CALL) || ins.group(GRP_BRANCH_RELATIVE)) &&
            i64(va) <= op.imm && op.imm < i64(va + MAX_DATA_COMPARE))
          reach = std::max(reach, u64(op.imm));
      if ((ins.mnemonic == "ret" || ins.mnemonic == "jmp" || ins.mnemonic == "int3" || starts_with(ins.mnemonic, "ret")) && reach < nxt)
        return ins.mnemonic != "int3" ? nxt : ins.address;
    }
    if (endp == window.size() || va + endp - nxt >= 15) return std::nullopt;
    at = size_t(nxt - va);
    size *= 2;
  }
}

}  // namespace verifier
