// What a DIFF reports: instructions as symbolised tokens, the mismatch category, and a unified diff.
#pragma once
#include <algorithm>
#include <array>
#include <functional>
#include <initializer_list>
#include <string>
#include <unordered_map>
#include <vector>

#include "compare.hpp"

namespace verifier {

// One symbolised operand:
//   r(reg) i(imm) rel(off) sym(key) msym(key, size) const(bytes) tbl(base, index, scale, off, size)
//   m(base, index, scale, disp, size, seg)
// Registers are canonical ids (reg_canon): equal exactly when their names are. Plain data, 64 bytes (a large
// function's diff holds a token per instruction).
struct Op {
  enum K : u8 { R, I, REL, SYM, MSYM, CONST, TBL, M };
  Key key;                           // SYM, MSYM (kind IMP for imports); CONST: the bytes as key.name
  i64 v = 0;                         // I: imm; REL: offset; TBL: offset; M: disp
  u16 base = 0, index = 0, seg = 0;  // R: base = the register
  u16 size = 0;
  K k;
  u8 scale = 0;
  std::string_view bytes() const { return key.name; }  // CONST: the constant's bytes (a view of the image)
  bool operator==(const Op& o) const {
    return k == o.k && base == o.base && index == o.index && seg == o.seg && key == o.key && v == o.v &&
           scale == o.scale && size == o.size;
  }
};
static_assert(sizeof(Op) <= 64);
// An instruction's operands, inline (at most 4)
class OpList {
 public:
  OpList() = default;
  OpList(std::initializer_list<Op> ops) {
    for (auto& o : ops) push_back(o);
  }
  void push_back(const Op& o) {
    if (n_ < ops_.size()) ops_[n_++] = o;
  }
  size_t size() const { return n_; }
  bool empty() const { return n_ == 0; }
  Op& operator[](size_t i) { return ops_[i]; }
  const Op& operator[](size_t i) const { return ops_[i]; }
  const Op* begin() const { return ops_.data(); }
  const Op* end() const { return ops_.data() + n_; }
  bool operator==(const OpList& o) const { return n_ == o.n_ && std::equal(begin(), end(), o.begin()); }

 private:
  std::array<Op, 4> ops_{};
  u8 n_ = 0;
};
struct Tok {
  Mnem mnemonic;
  OpList ops;
  bool operator==(const Tok& o) const { return mnemonic == o.mnemonic && ops == o.ops; }
};
using Toks = std::vector<Tok>;

Tok symbolise_one(const Insn& ins, u64 lo, u64 hi, const std::function<Key(u64)>& resolve, const Image& img,
                  bool const_by_value);
// every instruction of `c`, decoded again one at a time
Toks symbolise(const Code& c, const std::function<Key(u64)>& resolve, bool const_by_value);
std::string tok_text(const Tok& t, const NameOf& names);
std::string classify(const Toks& a, const Toks& b);

struct LongestMatch {
  size_t i, j, k;
};
LongestMatch find_longest_match(const std::vector<int>& a, const std::vector<int>& b, size_t alo, size_t ahi,
                                size_t blo, size_t bhi);
struct Opcode {
  char tag;
  size_t i1, i2, j1, j2;
};  // tag: e(qual) r(eplace) d(elete) i(nsert)
std::vector<Opcode> get_opcodes(const std::vector<int>& a,
                                const std::vector<int>& b);  // sequence alignment (report.cpp)

// the instructions' offsets in their functions and their tokens
std::vector<std::string> insn_diff(const std::vector<u32>& o_off, const std::vector<u32>& r_off, const Toks& ot,
                                   const Toks& rt, const NameOf& names, int context = 2, size_t limit = 200);

}  // namespace verifier
