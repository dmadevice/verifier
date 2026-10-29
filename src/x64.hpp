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

struct Mem {
  i64 disp;
  u16 base, index, segment;
  i8 scale;
};

// the immediate and the memory reference share storage; read the one `type` names
struct Operand {
  union {
    i64 imm = 0;   // OP_IMM
    Mem mem;       // OP_MEM
  };
  u16 reg = 0;     // OP_REG
  u8 type = 0, size = 0;
};

// An instruction's operands: up to three inline (almost every x86 instruction), all of them on the heap beyond
class OpVec {
 public:
  OpVec() = default;
  OpVec(const OpVec& o) : n_(o.n_) {
    std::copy(o.inl_, o.inl_ + kInline, inl_);
    if (o.more_) { more_.reset(new Operand[kMax]); std::copy(o.more_.get(), o.more_.get() + kMax, more_.get()); }
  }
  OpVec(OpVec&&) noexcept = default;
  OpVec& operator=(const OpVec& o) { if (this != &o) { OpVec t(o); *this = std::move(t); } return *this; }
  OpVec& operator=(OpVec&&) noexcept = default;
  const Operand* begin() const { return more_ ? more_.get() : inl_; }
  const Operand* end() const { return begin() + n_; }
  size_t size() const { return n_; }
  bool empty() const { return n_ == 0; }
  const Operand& operator[](size_t i) const { return begin()[i]; }
  void push_back(const Operand& o) {
    if (n_ < kInline && !more_) { inl_[n_++] = o; return; }
    if (!more_) { more_.reset(new Operand[kMax]); std::copy(inl_, inl_ + n_, more_.get()); }
    if (n_ < kMax) more_[n_++] = o;
  }

 private:
  static constexpr u8 kInline = 3, kMax = 4;   // x86 instructions have at most 4
  Operand inl_[kInline];
  u8 n_ = 0;
  std::unique_ptr<Operand[]> more_;
};

// A mnemonic: interned (one string per distinct mnemonic for the run), compared and concatenated as a string
class Mnem {
 public:
  Mnem() : s_(empty()) {}
  explicit Mnem(std::string_view s) : s_(&intern(s)) {}
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
  char raw[16] = {};          // the instruction's bytes (at most 15)
  OpVec ops;
  std::string_view bytes() const { return std::string_view(raw, size); }
  std::string op_str() const; // the operands as text (only reports need it)
  bool group(u8 g) const;
  bool branches() const;      // in GRP_JUMP / GRP_CALL / GRP_BRANCH_RELATIVE
};

const char* reg_name(u16 reg);       // a register's name ("" for none)
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
  std::vector<u32> image_base;        // per instruction: registers holding __ImageBase (bit per GPR)

  std::vector<Field> fields(const Insn& ins) const;
  std::vector<TableItem> table_region() const;
  std::vector<OutsideTable> outside_tables() const;
  bool image_relative(const Insn& ins, const Operand& op) const;

 private:
  void trim_padding();
};

std::vector<u32> image_base_regs(const std::vector<Insn>& insns, u64 base);
int gpr_index(u16 reg);   // the 64-bit GPR a register is part of (0..15), -1 otherwise

}  // namespace verifier
