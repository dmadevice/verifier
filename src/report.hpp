// What a DIFF reports: instructions as symbolised tokens, the mismatch category, and a unified diff.
#pragma once
#include <algorithm>
#include <array>
#include <functional>
#include <initializer_list>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "compare.hpp"
#include "matching.hpp"

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

// an instruction of `c` as a token (its operands decoded again, its addresses from its fields); every instruction
Tok symbolise_one(const Code& c, const Lean& l, const std::function<Key(u64)>& resolve, bool const_by_value);
Toks symbolise(const Code& c, const std::function<Key(u64)>& resolve, bool const_by_value);
std::string tok_text(const Tok& t, const NameOf& names);
Category classify(const Toks& a, const Toks& b);

// the original's RIP-relative operands that stand for their bytes where the rebuilt one's are compiler constants
void const_by_value(Tok& o, const Tok& r, const Image& O);
// the category from the mnemonics alone (classify's answer for them), or nullopt when both functions have the same
// mnemonics in the same order and classify needs the operands
std::optional<Category> classify_mnemonics(const Code& a, const Code& b);

// What the instruction diff needs beyond the two functions' code
struct DiffContext {
  std::function<Key(u64)> resolve;     // what a rebuilt address stands for
  const Matching* matching = nullptr;  // the pairs the comparison guessed and kept (after solve)
  NameOf names;                        // original VA -> name, for the lines shown
};
// The instruction diff of two functions: their instructions aligned as the comparison sees them (the same bytes
// outside the address fields, each field standing for the same thing; see Identities in report.cpp), as a unified
// diff of `context` lines around each change, `@N` heading each hunk (N: the original's instruction there), at most
// `limit` lines and then a count of the rest. A pair that reads the same says why it differs: its encoding (with its
// bytes), or branch targets not in each other's place.
struct CodeDiff {
  bool differs = false;                            // some instruction is not aligned with an equal one
  std::optional<std::pair<size_t, size_t>> first;  // the first difference: (original, rebuilt) instruction
  std::vector<std::string> lines;                  // when asked for
  // a line weighs the rebuilt bytes of an instruction with address fields (whether it is an encoding note, and its
  // bytes): the lines depend on where the rebuilt function is, not only on its code and what its fields stand for
  bool placed = false;
};
CodeDiff code_diff(const Code& oc, const Code& rc, const DiffContext& cx, bool want_lines, int context = 2,
                   size_t limit = 200);
// the alignment's self-check (VERIFIER_CHECK_ALIGN): a diff whose script is longer than the shortest is reported on
// stderr
bool& check_alignment();
// everything the diff reads of the rebuilt function's address fields beyond their values, in order, as one string:
// what each resolves to, and what it stands for in the alignment (for a literal, its bytes, which decide that)
std::string rebuilt_targets(const Code& oc, const Code& rc, const DiffContext& cx);

}  // namespace verifier
