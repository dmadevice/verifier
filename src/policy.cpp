#include "policy.hpp"

#include <map>
#include <string>

namespace verifier {

bool is_counted(Kind k) { return k == Kind::Function || k == Kind::Synthetic || k == Kind::Template; }
bool is_paired(Kind k) { return is_counted(k) || k == Kind::Library; }

void check_duplicates(const std::vector<Annotation>& anns) {
  std::map<u64, std::pair<std::string, bool>> seen;
  for (auto& a : anns) {
    if (!is_paired(a.kind)) continue;
    bool folded = a.flags.folded;
    auto it = seen.find(a.va);
    if (it != seen.end() && !(folded && it->second.second)) {
      throw RunError(1, "duplicate annotation " + hex(a.va) + ": " + it->second.first + " and " + std::string(a.path) +
                            ":" + std::to_string(a.line) + " (mark /OPT:ICF folds FOLDED)\n");
    }
    seen[a.va] = {std::string(a.path) + ":" + std::to_string(a.line), folded};
  }
}

const Linked* library_code(const Annotation& ann, const Original& orig) {
  if (!is_counted(ann.kind)) return nullptr;
  auto it = orig.linked.find(ann.va);
  return it == orig.linked.end() ? nullptr : &it->second;
}

}  // namespace verifier
