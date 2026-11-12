#include "problem.hpp"

#include <array>

namespace verifier {

namespace {
constexpr std::array<std::string_view, 13> kNames = {"reorder",  "regalloc",    "immediate", "inlining", "unexplained",
                                                     "encoding", "undecodable", "length",    "reference", "data",
                                                     "vtable",   "unwind",      "eh"};
}  // namespace

std::string_view category_name(Category c) { return kNames[size_t(c)]; }

std::optional<Category> category_named(std::string_view name) {
  for (size_t i = 0; i < kNames.size(); ++i)
    if (kNames[i] == name) return Category(i);
  return std::nullopt;
}

std::string Problem::text() const { return std::string(category_name(category)) + ": " + detail; }

}  // namespace verifier
