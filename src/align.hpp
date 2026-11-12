// Sequence alignment for the instruction diff: two sequences of small ints (equal exactly when the instructions they
// stand for are), aligned as a shortest edit script.
#pragma once
#include <cstddef>
#include <span>
#include <vector>

#include "util.hpp"

namespace verifier {

struct Opcode {
  char tag;  // e(qual) r(eplace) d(elete) i(nsert)
  size_t i1, i2, j1, j2;
};

// Each part (at first the whole) loses its common prefix and suffix and is split by Myers' O(ND) algorithm in linear
// space (the middle snake), which gives a shortest edit script. A part whose edit distance passes `max_cost` is split
// instead at the elements found once in each side, in their longest common order (patience diff), or where there are
// none, where the search got furthest; once the work for the whole alignment passes a budget linear in its size the
// parts left are replaced whole. Only those large parts may get a script longer than the shortest. The opcodes cover
// both sequences in order, adjacent ones never share a tag, and the result depends only on the inputs.
std::vector<Opcode> align(std::span<const u32> a, std::span<const u32> b, size_t max_cost = 1024);
// the length of a shortest edit script (deletions and insertions), without a cost limit: for checks
size_t edit_distance(std::span<const u32> a, std::span<const u32> b);

}  // namespace verifier
