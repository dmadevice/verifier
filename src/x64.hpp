// x64 code as the verifier compares it: decoded instructions (fadec) as plain records, and a function's code
// region with its switch tables.
#pragma once
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "pe.hpp"

namespace verifier {

constexpr u64 TABLE_SLACK = 0x1000;
enum OpType : u8 { OP_INVALID = 0, OP_REG = 1, OP_IMM = 2, OP_MEM = 3 };
enum Group : u8 { GRP_JUMP = 1, GRP_CALL = 2, GRP_BRANCH_RELATIVE = 4 };  // bits of Insn::gmask

// An operand in 16 bytes. OP_MEM: [base + index*scale + disp], with a segment override if `segment`.
struct Operand {
  i64 value = 0;   // OP_IMM: the immediate (a branch's: its target address); OP_MEM: the displacement
  u16 reg = 0;     // OP_REG: the register; OP_MEM: the base register (0: none)
  u16 index = 0;   // OP_MEM: the index register (0: none)
  u8 segment = 0;  // OP_MEM: the decoder's segment number + 1 (0: none); segment_reg() gives the register
  i8 scale = 0;    // OP_MEM
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
  size_t size() const {
    size_t n = 0;
    while (n < kMax && ops_[n].type != OP_INVALID) ++n;
    return n;
  }
  bool empty() const { return ops_[0].type == OP_INVALID; }
  const Operand& operator[](size_t i) const { return ops_[i]; }
  void set(size_t i, const Operand& o) { ops_[i] = o; }
  void truncate(size_t n) {
    for (size_t i = n; i < kMax; ++i) ops_[i].type = OP_INVALID;
  }  // slots from n on empty

 private:
  static constexpr size_t kMax = 4;
  Operand ops_[kMax];
};

// A mnemonic: interned (one string per distinct mnemonic for the run, numbered), compared and concatenated as a
// string
class Mnem {
 public:
  Mnem() : e_(empty()) {}
  explicit Mnem(std::string_view s) : e_(&intern(s)) {}
  Mnem(const char* s) : e_(&intern(s)) {}
  static Mnem from_id(u16 id);
  static size_t count();  // the mnemonics interned so far (their ids are below it)
  u16 id() const { return e_->id; }
  const std::string& str() const { return e_->s; }
  operator const std::string&() const { return e_->s; }
  operator std::string_view() const { return e_->s; }
  bool operator==(const Mnem& o) const { return e_ == o.e_; }
  bool operator==(const char* o) const { return e_->s == o; }
  bool operator==(const std::string& o) const { return e_->s == o; }

 private:
  struct Entry {
    std::string s;
    u16 id;
  };
  explicit Mnem(const Entry* e) : e_(e) {}
  static const Entry& intern(std::string_view s);
  static std::vector<std::unique_ptr<Entry>>& entries();
  static const Entry* empty() {
    static const Entry* e = &intern("");
    return e;
  }
  const Entry* e_;
};

struct Insn {
  u64 address = 0;
  u8 size = 0;
  u8 gmask = 0;  // the Group bits
  u8 imm_offset = 0, imm_size = 0, disp_offset = 0, disp_size = 0;
  u16 wmask = 0;  // 64-bit GPRs written (gpr_index bits)
  u16 type = 0;   // the decoder's instruction type
  Mnem mnemonic;
  OpVec ops;
  std::string op_str() const;  // the operands as text (only reports need it)
  std::string text() const { return mnemonic.str() + " " + op_str(); }
  bool group(Group g) const { return (gmask & g) != 0; }
  bool branches() const { return gmask != 0; }  // in any group
};

const char* reg_name(u16 reg);         // a register's name ("" for none)
u16 segment_reg(const Operand& op);    // a memory operand's segment register (0 for none)
u16 reg_canon(u16 reg);                // the first register id seen with this register's name (0 for none)
u16 reg_named(std::string_view name);  // the canonical id of the general-purpose register with this name (0 if none)
u16 reg_rip();

// An address field of an instruction: (offset in instruction, size, kind, value, access size)
enum FieldKind : u8 { F_ABS = 0, F_EXT = 1, F_IMG = 2, F_RIP = 3, F_TBL = 4 };          // ordered as the names sort
inline bool is_address(FieldKind k) { return k == F_RIP || k == F_IMG || k == F_ABS; }  // a field holding a VA
#pragma pack(push, 4)
struct Field {
  i64 value;             // target VA (function-relative table offset for F_TBL)
  u16 access;            // the memory operand's size (0: not one)
  u8 off : 4, size : 4;  // in the instruction (at most 15 bytes); at most 8 bytes
  FieldKind kind;
  bool operator<(const Field& o) const;
};
#pragma pack(pop)
static_assert(sizeof(Field) == 12, "a function's code keeps one per field");

struct TableItem {  // table_region(): ('e', target offset) or ('raw', bytes)
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

// An instruction as a function's code keeps it: where it is, its size and mnemonic, and its address fields. The
// operands are decoded again (Code::insn) when a report needs them.
struct Lean {
  static constexpr u64 MAX_OFF = (u64(1) << 23) - 1, MAX_FIELD = (u64(1) << 22) - 1, MAX_MNEM = (u64(1) << 11) - 1;
  u64 off : 23;    // from the function's start
  u64 field : 22;  // its first field in Code::field_list
  u64 mnem : 11;   // Mnem::id()
  u64 size : 4;
  u64 nfields : 3;  // at most 4: a branch target, a memory operand, two relocations
  // its operands depend on where it is: a branch, a RIP-relative or indexed memory operand, or a field
  u64 addressed : 1;
};
static_assert(sizeof(Lean) == 8, "a function's code keeps one per instruction");

// same size, and fields at the same places with the same kinds
bool same_layout(const Lean& a, std::span<const Field> fa, const Lean& b, std::span<const Field> fb);
// the same bytes outside the fields `f` (of the first)
bool same_outside_fields(std::string_view a, std::string_view b, std::span<const Field> f);

class CodeStore;
class Code {
 public:
  Code(const Image& img, u64 start, u64 end);
  const Image* img;
  u64 start, end;
  std::string_view code;  // the function's bytes, in the image
  bool relocated;
  std::vector<Lean> insns;
  std::vector<Field> field_list;  // every instruction's fields, in order
  std::map<i64, int> tables;      // function-relative table offset -> entry size
  i64 cut = 0;
  std::optional<i64> resume;  // code resumes here after the tables (hand-written switches)
  bool complete = false;

  u64 address(const Lean& i) const { return start + i.off; }
  std::string_view bytes(const Lean& i) const { return code.substr(i.off, i.size); }
  std::span<const Field> fields(const Lean& i) const { return {field_list.data() + i.field, i.nfields}; }
  Mnem mnemonic(const Lean& i) const { return Mnem::from_id(i.mnem); }
  Insn insn(const Lean& i) const;  // decoded again
  std::vector<TableItem> table_region() const;
  std::vector<OutsideTable> outside_tables() const;

 private:
  friend class CodeStore;  // makes a Code from what it kept of one
  Code() = default;
  std::string_view decoded_from_;  // the bytes the instructions were decoded from (`code` before trimming)
  size_t reloc_at_ = 0;            // add_fields: the first relocation not before the instruction
  void add_fields(const Insn& ins, u32 image_base);
  void trim_padding();
};

// per instruction, the GPRs (bit per gpr_index) that hold __ImageBase on entry; empty when none ever does
std::vector<u32> image_base_regs(const std::vector<Insn>& insns, u64 base);
int gpr_index(u16 reg);  // the 64-bit GPR a register is part of (0..15), -1 otherwise

}  // namespace verifier
