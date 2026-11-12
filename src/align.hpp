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

// Each part (at first the whole) loses its common prefix and suffix; then the elements found once in each side of it,
// in their longest common order, align with each other (patience diff) and the parts between them are aligned the
// same way; a part with no such element is split by Myers' O(ND) algorithm in linear space (the middle snake). A
// part whose edit distance passes `max_cost` is split where the search got furthest instead, and once the work for the
// whole alignment passes a budget linear in its size the parts left are replaced whole: the script stays valid but
// may not be the shortest. The opcodes cover both sequences in order, adjacent ones never share a tag, and the result
// depends only on the inputs.
//
// Patience before Myers: on the instruction diffs it reads the same or better where blocks move (they stay whole
// around their unique instructions), and Myers alone spent several times as long on large functions.
std::vector<Opcode> align(std::span<const u32> a, std::span<const u32> b, size_t max_cost = 1024);

}  // namespace verifier
