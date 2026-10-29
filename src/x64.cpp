#include "x64.hpp"

#include <fadec.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <memory>
#include <optional>
#include <stdexcept>
#include <type_traits>
#include <unordered_map>

namespace verifier {

namespace {

// -- registers: (fadec register type, index, size log2) packed into a u16, 0 for none ---------------------------

u16 make_reg(unsigned type, unsigned idx, unsigned sizelg) { return u16(1 + ((type & 15) << 9 | (idx & 63) << 3 | (sizelg & 7))); }
unsigned reg_type(u16 r) { return ((r - 1) >> 9) & 15; }
unsigned reg_idx(u16 r) { return ((r - 1) >> 3) & 63; }
unsigned reg_sizelg(u16 r) { return (r - 1) & 7; }

// GPR numbering: the hardware's (rax rcx rdx rbx rsp rbp rsi rdi r8..r15)
constexpr u32 gpr(unsigned i) { return 1u << i; }
constexpr u32 RAX = gpr(0), RCX = gpr(1), RDX = gpr(2), RBX = gpr(3), RSP = gpr(4), RBP = gpr(5), RSI = gpr(6), RDI = gpr(7);
constexpr u32 R11 = gpr(11);
constexpr u32 VOLATILE = RAX | RCX | RDX | gpr(8) | gpr(9) | gpr(10) | R11;   // clobbered by a call (x64 ABI)

u32 op_gpr(const FdInstr& fi, int k) {   // the GPR a register operand is part of, as a mask
  if (FD_OP_TYPE(&fi, k) != FD_OT_REG) return 0;
  unsigned idx = FD_OP_REG(&fi, k);
  switch (FD_OP_REG_TYPE(&fi, k)) {
    case FD_RT_GPL: return idx < 16 ? gpr(idx) : 0;
    case FD_RT_GPH: return gpr(idx - 4);
    default: return 0;
  }
}

// The GPRs an instruction writes, explicitly or implicitly. When unsure this says "written": a register wrongly
// thought to still hold __ImageBase would turn an ordinary displacement into an address field.
u32 written_gprs(const FdInstr& fi) {
  u32 w = 0;
  bool rep = FD_HAS_REP(&fi) || FD_HAS_REPNZ(&fi);
  switch (FD_TYPE(&fi)) {
    // the first operand is only read
    case FDI_CMP: case FDI_TEST: case FDI_BT: case FDI_PUSH: case FDI_JMP: case FDI_CALL: case FDI_JMPF:
    case FDI_CALLF: case FDI_OUT: case FDI_NOP: case FDI_PREFETCH: case FDI_CLFLUSH: case FDI_CLFLUSHOPT:
      break;
    default:
      w |= op_gpr(fi, 0);
  }
  switch (FD_TYPE(&fi)) {
    case FDI_XCHG: case FDI_XADD: case FDI_MULX: w |= op_gpr(fi, 1); break;
    case FDI_CMPXCHG: w |= RAX; break;
    case FDI_CMPXCHGD: w |= RAX | RDX; break;
    case FDI_MUL: case FDI_DIV: case FDI_IDIV: w |= RAX | RDX; break;
    case FDI_IMUL: if (FD_OP_TYPE(&fi, 1) == FD_OT_NONE) w |= RAX | RDX; break;
    case FDI_C_EX: w |= RAX; break;                      // cbw cwde cdqe
    case FDI_C_SEP: w |= RDX; break;                     // cwd cdq cqo
    case FDI_CPUID: w |= RAX | RBX | RCX | RDX; break;
    case FDI_RDTSC: case FDI_RDMSR: case FDI_RDPMC: case FDI_XGETBV: w |= RAX | RDX; break;
    case FDI_RDTSCP: w |= RAX | RDX | RCX; break;
    case FDI_LAHF: case FDI_XLATB: case FDI_IN: w |= RAX; break;
    case FDI_SYSCALL: w |= RCX | R11; break;
    case FDI_SSE_PCMPISTRI: case FDI_SSE_PCMPESTRI: case FDI_VPCMPISTRI: case FDI_VPCMPESTRI: w |= RCX; break;
    case FDI_LOOP: case FDI_LOOPZ: case FDI_LOOPNZ: w |= RCX; break;
    case FDI_MOVS: case FDI_CMPS: w |= RSI | RDI | (rep ? RCX : 0); break;
    case FDI_STOS: case FDI_SCAS: case FDI_INS: w |= RDI | (rep ? RCX : 0); break;
    case FDI_LODS: w |= RAX | RSI | (rep ? RCX : 0); break;
    case FDI_OUTS: w |= RSI | (rep ? RCX : 0); break;
    case FDI_PUSH: case FDI_POP: case FDI_PUSHF: case FDI_POPF: case FDI_CALL: case FDI_CALLF: case FDI_RET:
    case FDI_RETF: case FDI_IRET: case FDI_INT: case FDI_INT3: case FDI_INTO:
      w |= RSP; break;
    case FDI_ENTER: case FDI_LEAVE: w |= RSP | RBP; break;
    default: break;
  }
  return w;
}

u8 branch_bits(const FdInstr& fi) {   // GRP_JUMP / GRP_CALL / GRP_BRANCH_RELATIVE as bits 0..2
  u8 g = 0;
  switch (FD_TYPE(&fi)) {
    case FDI_CALL: case FDI_CALLF: g |= 2; break;
    case FDI_JMP: case FDI_JMPF: case FDI_JO: case FDI_JNO: case FDI_JC: case FDI_JNC: case FDI_JZ: case FDI_JNZ:
    case FDI_JBE: case FDI_JA: case FDI_JS: case FDI_JNS: case FDI_JP: case FDI_JNP: case FDI_JL: case FDI_JGE:
    case FDI_JLE: case FDI_JG: case FDI_JCXZ: case FDI_LOOP: case FDI_LOOPZ: case FDI_LOOPNZ:
      g |= 1; break;
    default: break;
  }
  if (FD_OP_TYPE(&fi, 0) == FD_OT_OFF) g |= 4;
  return g;
}

// Where an instruction's displacement and branch offset sit in its bytes: after the prefixes (legacy, REX,
// VEX, EVEX), the opcode, ModRM and SIB. disp_size is 0 when there is no displacement.
struct Layout { u8 opcode_end = 0, disp_offset = 0, disp_size = 0; };
Layout layout(const u8* b, size_t n, bool has_mem, unsigned addrsz) {
  Layout l;
  size_t p = 0;
  while (p < n) {   // legacy prefixes and REX
    u8 c = b[p];
    if (c == 0xf0 || c == 0xf2 || c == 0xf3 || c == 0x2e || c == 0x36 || c == 0x3e || c == 0x26 || c == 0x64 ||
        c == 0x65 || c == 0x66 || c == 0x67 || (c & 0xf0) == 0x40)
      ++p;
    else
      break;
  }
  if (p >= n) return l;
  bool legacy_map0 = false;
  u8 op = 0;
  if (b[p] == 0xc5) p += 2;                 // VEX, 2 bytes
  else if (b[p] == 0xc4) p += 3;            // VEX, 3 bytes
  else if (b[p] == 0x62) p += 4;            // EVEX
  else if (b[p] == 0x0f) {
    ++p;
    if (p < n && (b[p] == 0x38 || b[p] == 0x3a)) ++p;
  } else {
    legacy_map0 = true;
  }
  if (p >= n) return l;
  op = b[p++];
  l.opcode_end = u8(p);
  if (legacy_map0 && op >= 0xa0 && op <= 0xa3) {   // mov with an absolute address (moffs): no ModRM
    l.disp_offset = u8(p);
    l.disp_size = u8(addrsz);
    return l;
  }
  if (!has_mem || p >= n) return l;
  u8 modrm = b[p++];
  unsigned mod = modrm >> 6, rm = modrm & 7;
  if (mod != 3 && rm == 4 && p < n) {
    u8 sib = b[p++];
    if (mod == 0 && (sib & 7) == 5) { l.disp_offset = u8(p); l.disp_size = 4; return l; }
  }
  if (mod == 1) l.disp_size = 1;
  else if (mod == 2 || (mod == 0 && rm == 5)) l.disp_size = 4;
  if (l.disp_size) l.disp_offset = u8(p);
  return l;
}

// For a gather/scatter (vector-indexed memory): the VEX/EVEX vector length (0 128-bit, 1 256-bit, 2 512-bit) and
// the index register's size log2 (4 xmm, 5 ymm, 6 zmm), halved (`half`) for dword indices of qword elements.
struct Vsib { int len, index_sizelg; };
Vsib vsib_of(const u8* b, size_t n, bool half) {
  size_t p = 0;
  while (p < n && (b[p] == 0x66 || b[p] == 0x67 || b[p] == 0xf2 || b[p] == 0xf3 || b[p] == 0x2e || b[p] == 0x3e ||
                   b[p] == 0x26 || b[p] == 0x36 || b[p] == 0x64 || b[p] == 0x65))
    ++p;
  int len = 0;   // vector length: 0 128-bit, 1 256-bit, 2 512-bit
  if (p + 2 < n && b[p] == 0xc4) len = (b[p + 2] >> 2) & 1;
  else if (p + 1 < n && b[p] == 0xc5) len = (b[p + 1] >> 2) & 1;
  else if (p + 3 < n && b[p] == 0x62) len = (b[p + 3] >> 5) & 3;
  return Vsib{len, 4 + std::max(0, len - (half ? 1 : 0))};
}

// the mnemonic in fadec's text: prefix words (lock, rep, ...) and the instruction's name
std::string_view mnemonic_of(std::string_view text) {
  static const std::array<std::string_view, 15> prefixes = {"lock", "rep", "repnz", "xacquire", "xrelease", "notrack",
                                                           "hint-taken", "addr32", "addr16", "es", "cs", "ss", "ds",
                                                           "fs", "gs"};
  size_t p = 0;
  for (;;) {
    size_t e = text.find(' ', p);
    std::string_view word = text.substr(p, e == std::string_view::npos ? std::string_view::npos : e - p);
    bool prefix = std::find(prefixes.begin(), prefixes.end(), word) != prefixes.end();
    if (!prefix || e == std::string_view::npos) return text.substr(0, e == std::string_view::npos ? text.size() : e);
    p = e + 1;
  }
}

// An instruction's mnemonic, as fadec's formatter spells it, and whether it is a gather/scatter (`vsib`, with
// `half` for dword indices of qword elements). It depends only on the fields in the key (type, prefixes, operand
// and address size, the first operand's kind and size, segment), so each is formatted once.
struct MnemInfo { Mnem mnemonic; bool vsib, half; };
const MnemInfo& mnemonic(const FdInstr& fi) {
  int t0 = FD_OP_TYPE(&fi, 0);
  u64 key = u64(FD_TYPE(&fi)) | u64(FD_HAS_LOCK(&fi) ? 1 : 0) << 16 | u64(FD_HAS_REP(&fi) ? 1 : 0) << 17 |
            u64(FD_HAS_REPNZ(&fi) ? 1 : 0) << 18 | u64(FD_OPSIZELG(&fi)) << 19 | u64(FD_ADDRSIZELG(&fi)) << 22 |
            u64(t0) << 25 | u64(t0 != FD_OT_NONE ? FD_OP_SIZELG(&fi, 0) + 1 : 0) << 28 |
            u64(t0 == FD_OT_REG ? FD_OP_REG_TYPE(&fi, 0) : 0) << 33 | u64(FD_SEGMENT(&fi)) << 38 |
            u64(FD_HAS_3E(&fi) ? 1 : 0) << 45;
  // a direct-mapped table in front of the map: one probe for almost every instruction
  struct Slot { u64 key = ~0ull; const MnemInfo* info = nullptr; };
  static std::array<Slot, 4096> recent;
  Slot& slot = recent[(key ^ key >> 25 ^ key >> 38) & 4095];
  if (slot.key == key) return *slot.info;
  static std::unordered_map<u64, MnemInfo> cache;
  auto it = cache.find(key);
  if (it == cache.end()) {
    char text[128];
    fd_format(&fi, text, sizeof text);
    std::string_view m = mnemonic_of(text);
    bool vsib = m.find("gather") != std::string_view::npos || m.find("scatter") != std::string_view::npos;
    bool half = m.ends_with("dq") || m.ends_with("dpd");
    it = cache.emplace(key, MnemInfo{Mnem(m), vsib, half}).first;
  }
  slot = {key, &it->second};
  return it->second;
}

// One instruction from at most `n` bytes at `p` (address `addr`); false when the bytes do not decode.
bool decode_one(const u8* p, size_t n, u64 addr, Insn& r) {
  FdInstr fi;
  int len = fd_decode(p, n, 64, 0, &fi);
  if (len <= 0) return false;
  r = Insn();
  r.address = addr;
  r.size = u8(len);
  r.type = u16(FD_TYPE(&fi));
  const MnemInfo& mi = mnemonic(fi);
  r.mnemonic = mi.mnemonic;
  unsigned addrlg = FD_ADDRSIZELG(&fi);
  std::optional<Vsib> vsib;
  if (mi.vsib) vsib = vsib_of(p, size_t(len), mi.half);
  bool has_mem = false;
  for (int k = 0; k < 4; ++k) {
    int t = FD_OP_TYPE(&fi, k);
    if (t == FD_OT_NONE) break;
    Operand op;
    op.size = u8(FD_OP_SIZE(&fi, k));
    switch (t) {
      case FD_OT_REG:
        op.type = OP_REG;
        op.reg = make_reg(FD_OP_REG_TYPE(&fi, k), FD_OP_REG(&fi, k), unsigned(FD_OP_SIZELG(&fi, k)));
        break;
      case FD_OT_IMM:
        op.type = OP_IMM;
        op.value = FD_OP_IMM(&fi, k);
        break;
      case FD_OT_OFF:   // a branch target, relative to the next instruction
        op.type = OP_IMM;
        op.value = i64(addr + u64(len) + u64(FD_OP_IMM(&fi, k)));
        break;
      default: {        // memory (also an AVX-512 broadcast)
        has_mem = true;
        op.type = OP_MEM;
        unsigned base = FD_OP_BASE(&fi, k), index = FD_OP_INDEX(&fi, k);
        op.reg = base == FD_REG_NONE ? 0 : make_reg(FD_RT_GPL, base, addrlg);
        op.index = index == FD_REG_NONE ? 0
                   : vsib          ? make_reg(FD_RT_VEC, index, unsigned(vsib->index_sizelg))
                                   : make_reg(FD_RT_GPL, index, addrlg);
        if (vsib) op.size = u8(16 << vsib->len);   // the vector the elements are gathered from, not one element
        op.scale = i8(1 << FD_OP_SCALE(&fi, k));
        op.value = FD_OP_DISP(&fi, k);
        op.segment = FD_SEGMENT(&fi) == FD_REG_NONE ? 0 : u8(FD_SEGMENT(&fi) + 1);
      }
    }
    r.ops.push_back(op);
  }
  r.gmask = branch_bits(fi);
  r.wmask = u16(written_gprs(fi));
  Layout l = layout(p, size_t(len), has_mem, 1u << addrlg);
  r.disp_offset = l.disp_offset;
  r.disp_size = l.disp_size;
  if (r.gmask & 4) {   // the branch offset ends the instruction
    r.imm_offset = l.opcode_end;
    r.imm_size = u8(len - l.opcode_end);
  }
  return true;
}

u8 group_bit(u8 g) { return g == GRP_JUMP ? 1 : g == GRP_CALL ? 2 : g == GRP_BRANCH_RELATIVE ? 4 : 0; }

}  // namespace

const Mnem::Entry& Mnem::intern(std::string_view s) {
  static SvMap<const Entry*> table;
  auto it = table.find(s);
  if (it == table.end()) {
    auto& all = entries();
    if (all.size() > 0xffff) throw std::runtime_error("more than 65536 distinct mnemonics");
    all.push_back(std::make_unique<Entry>(Entry{std::string(s), u16(all.size())}));
    it = table.emplace(std::string(s), all.back().get()).first;
  }
  return *it->second;
}
std::vector<std::unique_ptr<Mnem::Entry>>& Mnem::entries() {
  static std::vector<std::unique_ptr<Entry>> all;
  return all;
}
Mnem Mnem::from_id(u16 id) { return Mnem(entries()[id].get()); }

static_assert(std::is_trivially_copyable_v<Insn> && sizeof(Insn) <= 96, "instructions are decoded in bulk: keep them flat");

bool Insn::group(u8 g) const { return (gmask & group_bit(g)) != 0; }
bool Insn::branches() const { return (gmask & 7) != 0; }

std::string Insn::op_str() const {
  auto size_ptr = [](int n) -> std::string {
    switch (n) {
      case 1: return "byte ptr ";
      case 2: return "word ptr ";
      case 4: return "dword ptr ";
      case 6: return "fword ptr ";
      case 8: return "qword ptr ";
      case 10: return "tbyte ptr ";
      case 16: return "xmmword ptr ";
      case 32: return "ymmword ptr ";
      case 64: return "zmmword ptr ";
      default: return "";
    }
  };
  std::string out;
  for (auto& op : ops) {
    if (!out.empty()) out += ", ";
    if (op.type == OP_REG) {
      out += reg_name(op.reg);
    } else if (op.type == OP_IMM) {
      out += branches() ? hex(u64(op.imm())) : hex_signed(op.imm());
    } else {
      std::string addr = reg_name(op.base());
      if (op.index) {
        if (!addr.empty()) addr += "+";
        addr += reg_name(op.index);
        if (op.scale > 1) addr += "*" + std::to_string(op.scale);
      }
      if (op.disp() || addr.empty()) {
        std::string d = hex_signed(op.disp());
        addr += addr.empty() || d[0] == '-' ? d : "+" + d;
      }
      out += size_ptr(op.size) + (op.segment ? std::string(reg_name(segment_reg(op))) + ":" : "") + "[" + addr + "]";
    }
  }
  return out;
}

const char* reg_name(u16 reg) {
  static std::unordered_map<u16, std::string> names;
  if (!reg) return "";
  auto it = names.find(reg);
  if (it == names.end()) {
    char buf[16];
    fd_format_reg(FdRegType(reg_type(reg)), FdReg(reg_idx(reg)), reg_sizelg(reg), buf);
    it = names.emplace(reg, buf).first;
  }
  return it->second.c_str();
}
u16 segment_reg(const Operand& op) { return op.segment ? make_reg(FD_RT_SEG, op.segment - 1u, 1) : 0; }
u16 reg_canon(u16 reg) {
  static std::unordered_map<u16, u16> canon;
  static std::unordered_map<std::string_view, u16> by_name;
  if (!reg) return 0;
  auto it = canon.find(reg);
  if (it == canon.end()) it = canon.emplace(reg, by_name.emplace(reg_name(reg), reg).first->second).first;
  return it->second;
}
u16 reg_named(std::string_view name) {
  for (unsigned idx = 0; idx <= FD_REG_IP; ++idx)
    for (unsigned sizelg = 0; sizelg < 4; ++sizelg) {
      char buf[16] = {};
      fd_format_reg(FD_RT_GPL, FdReg(idx), sizelg, buf);
      if (name == buf) return reg_canon(make_reg(FD_RT_GPL, idx, sizelg));
    }
  return 0;
}
u16 reg_rip() { return make_reg(FD_RT_GPL, FD_REG_IP, 3); }
int gpr_index(u16 reg) {
  if (!reg) return -1;
  unsigned idx = reg_idx(reg);
  switch (reg_type(reg)) {
    case FD_RT_GPL: return idx < 16 ? int(idx) : -1;
    case FD_RT_GPH: return int(idx) - 4;
    default: return -1;
  }
}

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
  std::vector<Insn> out;
  const u8* p = reinterpret_cast<const u8*>(code.data());
  size_t off = 0;
  Insn ins;
  while (off < code.size() && decode_one(p + off, code.size() - off, start + off, ins)) {
    off += ins.size;
    out.push_back(std::move(ins));
  }
  return out;
}

Code::Code(const Image& im, u64 s, u64 e) : img(&im), start(s), end(e) {
  code = decoded_from_ = im.bytes(s, i64(e) - i64(s));
  relocated = im.reloc_lower_bound(e) > im.reloc_lower_bound(s);
  i64 frva = i64(s - im.base), erva = i64(e - im.base);
  i64 n = i64(code.size());
  cut = n;
  u16 rip = reg_rip();
  static std::vector<Insn> ins_;   // the decoded instructions, kept only while the lean form is made
  std::vector<Insn>& all = ins_;
  all.clear();
  {
    const u8* p = reinterpret_cast<const u8*>(code.data());
    size_t off = 0;
    Insn ins;
    while (off < code.size() && decode_one(p + off, code.size() - off, s + off, ins)) {
      i64 k = i64(off);
      if (k >= cut) break;
      off += ins.size;
      for (auto& op : ins.ops) {
        if (op.type == OP_MEM && op.base() != rip && op.index && frva <= op.disp() &&
            op.disp() < erva + i64(TABLE_SLACK)) {
          i64 t = op.disp() - frva;
          auto it = tables.find(t);
          tables[t] = std::max(it == tables.end() ? 0 : it->second, int(op.size));
          if (t < cut) cut = std::max(t, i64(ins.address + ins.size - s));
        }
      }
      all.push_back(ins);
    }
  }
  // alignment nops after the last ret/jmp (before a switch table) are padding, not code
  while (all.size() > 1 && all.back().type == FDI_NOP &&
         (all[all.size() - 2].type == FDI_RET || all[all.size() - 2].type == FDI_JMP) &&
         i64(all.back().address + all.back().size - s) == cut) {
    cut = i64(all.back().address - s);
    all.pop_back();
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
    auto more = decode_linear(code.substr(size_t(*resume)), s + u64(*resume));
    for (auto& i : more) all.push_back(i);
  }
  i64 decoded = 0;
  for (auto& i : all) decoded += i.size;
  complete = decoded == cut + (resume ? n - *resume : 0);
  std::vector<u32> image_base = image_base_regs(all, im.base);
  insns.reserve(all.size());
  for (size_t k = 0; k < all.size(); ++k) {
    const Insn& ins = all[k];
    Lean l{u32(ins.address - s), u32(field_list.size()), ins.mnemonic.id(), ins.size, 0, ins.branches()};
    add_fields(ins, k < image_base.size() ? image_base[k] : 0);
    l.nfields = u8(field_list.size() - l.field);
    l.addressed = l.addressed || l.nfields;
    for (auto& op : ins.ops) l.addressed = l.addressed || (op.type == OP_MEM && (op.base() == rip || op.index));
    insns.push_back(l);
  }
  trim_padding();
}

bool same_layout(const Lean& a, std::span<const Field> fa, const Lean& b, std::span<const Field> fb) {
  if (a.size != b.size || fa.size() != fb.size()) return false;
  for (size_t z = 0; z < fa.size(); ++z)
    if (fa[z].off != fb[z].off || fa[z].size != fb[z].size || fa[z].kind != fb[z].kind) return false;
  return true;
}

bool same_outside_fields(std::string_view a, std::string_view b, std::span<const Field> f) {
  if (a.size() != b.size()) return false;
  u32 masked = 0;   // instructions are at most 15 bytes; a field can reach past the end
  for (auto& x : f)
    for (size_t i = x.off; i < size_t(x.off) + x.size && i < a.size(); ++i) masked |= 1u << i;
  for (size_t i = 0; i < a.size(); ++i)
    if (!(masked >> i & 1) && a[i] != b[i]) return false;
  return true;
}

Insn Code::insn(const Lean& l) const {
  Insn ins;
  // the same bytes, limit and address as the first decode
  decode_one(reinterpret_cast<const u8*>(decoded_from_.data()) + l.off, decoded_from_.size() - l.off, start + l.off, ins);
  return ins;
}

std::vector<Insn> Code::decoded() const {
  std::vector<Insn> out;
  out.reserve(insns.size());
  for (auto& l : insns) out.push_back(insn(l));
  return out;
}

void Code::trim_padding() {
  i64 n = i64(code.size());
  if (cut < n && !resume) {
    for (auto& [t, sz] : tables) if (t < n) return;
    code = code.substr(0, size_t(cut));
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

void Code::add_fields(const Insn& ins, u32 image_base) {
  size_t first = field_list.size();
  auto add = [&](int off, int size, FieldKind kind, i64 value, int access) {
    field_list.push_back(Field{value, access, u8(off), u8(size), kind});
  };
  i64 frva = i64(start - img->base);
  if (ins.branches()) {
    for (auto& op : ins.ops)
      if (op.type == OP_IMM && !(i64(start) <= op.imm() && op.imm() < i64(end)) && ins.imm_size)
        add(ins.imm_offset, ins.imm_size, F_EXT, op.imm(), 0);
  }
  // [__ImageBase register + disp] (or as the index) addressing a part of the image
  auto image_relative = [&](const Operand& op) {
    if (!image_base) return false;
    u32 regs = 0;
    for (u16 r : {op.base(), op.index}) if (r) { int g = gpr_index(r); if (g >= 0) regs |= 1u << g; }
    return (image_base & regs) && op.disp() > 0 && img->flags(img->base + u64(op.disp())).has_value();
  };
  for (auto& op : ins.ops) {
    if (op.type != OP_MEM) continue;
    int size = ins.type == FDI_LEA ? 0 : op.size;   // bytes read there; lea only takes the address
    if (op.base() == reg_rip()) {
      add(ins.disp_offset, 4, F_RIP, i64(ins.address + ins.size) + op.disp(), size);
    } else if (op.index && tables.count(op.disp() - frva)) {
      add(ins.disp_offset, ins.disp_size, F_TBL, op.disp() - frva, 0);
    } else if (image_relative(op)) {
      add(ins.disp_offset, ins.disp_size, F_IMG, i64(img->base) + op.disp(), size);
    }
  }
  if (relocated) {
    size_t i = img->reloc_lower_bound(ins.address);
    while (i < img->reloc_sorted.size() && img->reloc_sorted[i] < ins.address + ins.size) {
      u64 site = img->reloc_sorted[i];
      add(int(site - ins.address), 8, F_ABS, i64(img->u64_at(site)), 0);
      ++i;
    }
  }
  if (field_list.size() - first > 1) std::sort(field_list.begin() + long(first), field_list.end());
}

std::vector<u32> image_base_regs(const std::vector<Insn>& insns, u64 base) {
  // must-analysis over the instructions' control flow: which GPRs hold __ImageBase on entry to each one
  size_t n = insns.size();
  std::vector<u32> kill(n), gen(n);
  bool any_gen = false;
  for (size_t k = 0; k < n; ++k) {
    const Insn& ins = insns[k];
    u32 kl = ins.wmask;
    if (ins.group(GRP_CALL)) kl |= VOLATILE;
    u32 g = 0;
    if (ins.type == FDI_LEA && ins.ops.size() == 2 && ins.ops[1].type == OP_MEM) {
      const Operand& m = ins.ops[1];
      if (m.base() == reg_rip() && !m.index && u64(i64(ins.address + ins.size) + m.disp()) == base) {
        int x = gpr_index(ins.ops[0].reg);
        if (x >= 0) g = 1u << x;
      }
    }
    kill[k] = kl; gen[k] = g;
    any_gen |= g != 0;
  }
  // nothing loads __ImageBase: no register holds it anywhere (an empty vector says so for every instruction)
  if (!any_gen) return {};
  auto index_of = [&](u64 a) -> long {   // instructions are in address order
    auto it = std::lower_bound(insns.begin(), insns.end(), a, [](const Insn& i, u64 x) { return i.address < x; });
    return it != insns.end() && it->address == a ? long(it - insns.begin()) : -1;
  };
  // predecessors as flat arrays (CSR): fall-through from k-1, and jumps with an immediate target
  std::vector<u32> npred(n + 1, 0);
  std::vector<std::pair<u32, u32>> edges;   // (to, from)
  edges.reserve(n + n / 4);
  std::vector<u32> switches;
  auto falls = [](const Insn& ins) {   // execution can continue with the next instruction
    switch (ins.type) {
      case FDI_JMP: case FDI_UD2: case FDI_INT3: case FDI_RET: case FDI_RETF: return false;
      default: return true;
    }
  };
  for (size_t k = 0; k < n; ++k) {
    const Insn& ins = insns[k];
    if (k + 1 < n && falls(ins)) edges.emplace_back(u32(k + 1), u32(k));
    if (ins.group(GRP_JUMP) && !ins.ops.empty() && ins.ops[0].type == OP_IMM) {
      long t = index_of(u64(ins.ops[0].imm()));
      if (t >= 0) edges.emplace_back(u32(t), u32(k));
    }
    if (ins.type == FDI_JMP && !ins.ops.empty() && ins.ops[0].type == OP_REG) switches.push_back(u32(k));
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
            i64(va) <= op.imm() && op.imm() < i64(va + MAX_DATA_COMPARE))
          reach = std::max(reach, u64(op.imm()));
      if ((ins.type == FDI_RET || ins.type == FDI_RETF || ins.type == FDI_JMP || ins.type == FDI_INT3) && reach < nxt)
        return ins.type != FDI_INT3 ? nxt : ins.address;
    }
    if (endp == window.size() || va + endp - nxt >= 15) return std::nullopt;
    at = size_t(nxt - va);
    size *= 2;
  }
}

}  // namespace verifier
