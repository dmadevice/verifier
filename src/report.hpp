// What a DIFF reports: instructions as symbolised tokens, the mismatch category, and a unified diff.
#pragma once
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

#include "compare.hpp"

namespace verifier {

// One symbolised operand:
//   r(reg) i(imm) rel(off) sym(key) msym(key, size) const(hex) tbl(base, index, scale, off, size)
//   m(base, index, scale, disp, size, seg)
// Registers are canonical ids (reg_canon): equal exactly when their names are.
struct Op {
  enum K : u8 { R, I, REL, SYM, MSYM, CONST, TBL, M } k;
  u16 base = 0, index = 0, seg = 0;   // R: base = the register
  std::string hex;                    // CONST: the bytes in hex
  Key key;                            // SYM, MSYM (kind IMP for imports)
  i64 v = 0;                          // I: imm; REL: offset; TBL: offset; M: disp
  int scale = 0, size = 0;
  bool operator==(const Op& o) const {
    return k == o.k && base == o.base && index == o.index && seg == o.seg && hex == o.hex && key == o.key && v == o.v &&
           scale == o.scale && size == o.size;
  }
};
struct Tok {
  Mnem mnemonic;
  std::vector<Op> ops;
  bool operator==(const Tok& o) const { return mnemonic == o.mnemonic && ops == o.ops; }
};
using Toks = std::vector<Tok>;

Tok symbolise_one(const Insn& ins, u64 lo, u64 hi, const std::function<Key(u64)>& resolve, const Image& img,
                  bool const_by_value);
Toks symbolise(const std::vector<Insn>& insns, u64 lo, u64 hi, const std::function<Key(u64)>& resolve, const Image& img,
               bool const_by_value);
std::string tok_text(const Tok& t, const std::unordered_map<u64, std::string>& names);
std::string classify(const Toks& a, const Toks& b);

struct LongestMatch { size_t i, j, k; };
LongestMatch find_longest_match(const std::vector<int>& a, const std::vector<int>& b, size_t alo, size_t ahi, size_t blo, size_t bhi);
struct Opcode { char tag; size_t i1, i2, j1, j2; };   // tag: e(qual) r(eplace) d(elete) i(nsert)
std::vector<Opcode> get_opcodes(const std::vector<int>& a, const std::vector<int>& b);   // sequence alignment (report.cpp)

std::vector<std::string> insn_diff(const std::vector<Insn>& oi, const std::vector<Insn>& ri, const Toks& ot, const Toks& rt,
                                   const std::unordered_map<u64, std::string>& names, int context = 2, size_t limit = 200);

}  // namespace verifier
