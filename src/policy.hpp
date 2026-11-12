// Project policy: what the comparison's verdicts mean for a decompilation project, kept apart from the engine (pe,
// x64, layouts, compare*, matching, report) and the inputs (inputs, annotations, pairing):
//   - which annotation kinds are compared and which are counted as decompiled;
//   - FOLDED: several annotations on one address only when all of them say so;
//   - LIBCODE: a counted annotation on code the configuration attributes to a linked library.
// The module tag annotations carry is the configuration's `module` (annotations.cpp reads only that module's).
#pragma once
#include <vector>

#include "annotations.hpp"
#include "inputs.hpp"

namespace verifier {

bool is_counted(Kind k);  // FUNCTION SYNTHETIC TEMPLATE: decompiled code, compared and counted
bool is_paired(Kind k);   // the counted kinds and LIBRARY: compared

// throws (RunError, status 1) when two compared annotations claim one address without both saying FOLDED
void check_duplicates(const std::vector<Annotation>& anns);

// the linked library an annotation's code belongs to, when it is counted (LIBCODE: library code is linked, not
// decompiled); nullptr otherwise
const Linked* library_code(const Annotation& ann, const Original& orig);

}  // namespace verifier
