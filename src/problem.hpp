// What a comparison finds: a problem, its category and what is wrong in words. The category is typed; its name is
// only for output (the report, stdout, the tests' expectations).
#pragma once
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "util.hpp"

namespace verifier {

// A DIFF's category. The first five say how the instruction streams differ (classify()), the next three that the
// instructions are the same but not their bytes or size, the rest what something referenced differs in.
enum class Category : u8 {
  Reorder,      // the same instructions in another order
  Regalloc,     // the same instructions, other registers
  Immediate,    // the same instructions, other immediates or displacements
  Inlining,     // another number of calls, or many more or fewer instructions
  Unexplained,  // the instruction streams differ otherwise
  Encoding,     // an instruction's bytes, or a switch table
  Undecodable,  // bytes that do not decode
  Length,       // another number of instructions or bytes
  Reference,    // an address field names another target
  Data,         // referenced data differs
  Vtable,       // a referenced vtable's slots or RTTI differ
  Unwind,       // .pdata or UNWIND_INFO
  Eh,           // the language handler's data (C++ EH, GS, SEH)
};
std::string_view category_name(Category c);  // as reported: "reorder", ...
std::optional<Category> category_named(std::string_view name);

struct Problem {
  Category category;
  std::string detail;
  std::string text() const;  // "<category>: <detail>", as the report gives it
  bool operator==(const Problem&) const = default;
};
using Problems = std::vector<Problem>;

}  // namespace verifier
