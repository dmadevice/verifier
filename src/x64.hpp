// x64 code as the verifier compares it: decoded instructions (fadec) as plain records, and a function's code
// region with its switch tables.
#pragma once
#include <map>
#include <ostream>
#include <string_view>
#include <unordered_map>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "pe.hpp"

namespace verifier {

constexpr u64 TABLE_SLACK = 0x1000;
enum OpType : u8 { OP_INVALID = 0, OP_REG = 1, OP_IMM = 2, OP_MEM = 3 };
enum Group : u8 { GRP_JUMP = 1, GRP_CALL = 2, GRP_BRANCH_RELATIVE = 7 };

// An operand in 16 bytes. OP_MEM: [base + index*scale + disp], with a segment override if `segment`.
struct Operand {
  i64 value = 0;    // OP_IMM: the immediate (a branch's: its target address); OP_MEM: the displacement
  u16 reg = 0;      // OP_REG: the register; OP_MEM: the base register (0: none)
  u16 index = 0;    // OP_MEM: the index register (0: none)
  u8 segment = 0;   // OP_MEM: the decoder's segment number + 1 (0: none); segment_reg() gives the register
  i8 scale = 0;     // OP_MEM
  u8 type = 0, size = 0;
  i64 imm() const { return value; }
  i64 disp() const { return value; }
  u16 base() const { return reg; }
};

// An instruction's operands, all inline (x86 instructions have at most 4); the used ones come first
class OpVec {
 public:
  const Operand* begin() const { return ops_; }
  const Operand* end() const { return ops_ + size(); }
  size_t size() const { size_t n = 0; while (n < kMax && ops_[n].type != OP_INVALID) ++n; return n; }
  bool empty() const { return ops_[0].type == OP_INVALID; }
  const Operand& operator[](size_t i) const { return ops_[i]; }
  void push_back(const Operand& o) { size_t n = size(); if (n < kMax) ops_[n] = o; }

 private:
  static constexpr size_t kMax = 4;
  Operand ops_[kMax];
};

// A mnemonic: interned (one string per distinct mnemonic for the run), compared and concatenated as a string
class Mnem {
 public:
  Mnem() : s_(empty()) {}
  explicit Mnem(std::string_view s) : s_(&intern(s)) {}
  Mnem(const char* s) : s_(&intern(s)) {}
  const std::string& str() const { return *s_; }
  operator const std::string&() const { return *s_; }
  operator std::string_view() const { return *s_; }
  bool operator==(const Mnem& o) const { return s_ == o.s_; }
  bool operator==(const char* o) const { return *s_ == o; }
  bool operator==(const std::string& o) const { return *s_ == o; }

 private:
  static const std::string& intern(std::string_view s);
  static const std::string* empty() {
    static const std::string* e = &intern("");
    return e;
  }
  const std::string* s_;
};
inline std::string operator+(const Mnem& m, const char* s) { return m.str() + s; }
inline std::string operator+(const Mnem& m, const std::string& s) { return m.str() + s; }
inline std::string operator+(const std::string& s, const Mnem& m) { return s + m.str(); }
inline std::string operator+(std::string&& s, const Mnem& m) { return std::move(s) + m.str(); }
inline std::ostream& operator<<(std::ostream& o, const Mnem& m) { return o << m.str(); }

struct Insn {
  u64 address = 0;
  u8 size = 0;
  u8 gmask = 0;               // GRP_JUMP / GRP_CALL / GRP_BRANCH_RELATIVE as bits 0..2
  u8 imm_offset = 0, imm_size = 0, disp_offset = 0, disp_size = 0;
  u16 wmask = 0;              // 64-bit GPRs written (gpr_index bits)
  u16 type = 0;               // the decoder's instruction type
  Mnem mnemonic;
  OpVec ops;
  std::string op_str() const; // the operands as text (only reports need it)
  bool group(u8 g) const;
  bool branches() const;      // in GRP_JUMP / GRP_CALL / GRP_BRANCH_RELATIVE
};

const char* reg_name(u16 reg);       // a register's name ("" for none)
u16 segment_reg(const Operand& op);  // a memory operand's segment register (0 for none)
u16 reg_canon(u16 reg);              // the first register id seen with this register's name (0 for none)
u16 reg_named(std::string_view name); // the canonical id of the general-purpose register with this name (0 if none)
u16 reg_rip();

// An address field of an instruction: (offset in instruction, size, kind, value, access size)
enum FieldKind : u8 { F_ABS = 0, F_EXT = 1, F_IMG = 2, F_RIP = 3, F_TBL = 4 };   // ordered as the names sort
const char* field_kind_name(FieldKind k);
struct Field {
  int off, size;
  FieldKind kind;
  i64 value;     // target VA (function-relative table offset for F_TBL)
  int access;
  bool operator<(const Field& o) const;
};

struct TableItem {   // table_region(): ('e', target offset) or ('raw', bytes)
  bool entry;
  i64 target;
  Bytes raw;
  bool operator==(const TableItem& o) const { return entry == o.entry && target == o.target && raw == o.raw; }
};
struct OutsideTable {
  i64 offset;
  bool dword;
  std::vector<i64> entries;
  Bytes raw;
  bool operator==(const OutsideTable& o) const = default;
};

// Decode instructions from `code` at address `start`, linearly, until an undecodable byte (or `limit` bytes).
std::vector<Insn> decode_linear(std::string_view code, u64 start);

class Code {
 public:
  Code(const Image& img, u64 start, u64 end);
  const Image* img;
  u64 start, end;
  Bytes code;
  bool relocated;
  std::vector<Insn> insns;
  std::map<i64, int> tables;          // function-relative table offset -> entry size
  i64 cut = 0;
  std::optional<i64> resume;          // code resumes here after the tables (hand-written switches)
  bool complete = false;
  std::vector<u32> image_base;        // image_base_regs() of the instructions

  std::string_view bytes(const Insn& ins) const { return std::string_view(code).substr(size_t(ins.address - start), ins.size); }
  std::vector<Field> fields(const Insn& ins) const;
  std::vector<TableItem> table_region() const;
  std::vector<OutsideTable> outside_tables() const;
  bool image_relative(const Insn& ins, const Operand& op) const;

 private:
  void trim_padding();
};

// per instruction, the GPRs (bit per gpr_index) that hold __ImageBase on entry; empty when none ever does
std::vector<u32> image_base_regs(const std::vector<Insn>& insns, u64 base);
int gpr_index(u16 reg);   // the 64-bit GPR a register is part of (0..15), -1 otherwise

}  // namespace verifier
