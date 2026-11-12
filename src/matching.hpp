// What the comparison pairs beyond the names: the matching of original and rebuilt objects that no annotation or name
// pairs, solved for all functions at once instead of decided by whichever comparison meets them first.
//
// A run compares in two passes over the same code (Comparer):
//   explore  every compared annotation (a root) once, and everything its comparison reaches. Where the comparison
//            would have to guess (an unnamed rebuilt function, vtable or table standing for an original one, a local
//            static's place, a build hash in a name, a shared FuncInfo), it registers a node and assumes it holds.
//            Each comparison unit (a function, data or vtable pair) keeps the problems it found with every assumption
//            held, and the nodes it depends on.
//   solve    keeps the nodes that hold together: a unit holds when it found no problems and every node it depends on
//            holds (the greatest fixed point, so tables or vtables that point at each other hold together), and each
//            class's rule (below) picks among nodes that compete; a node a rule drops is gone for good, and the
//            fixed point is taken again until nothing changes.
//   judge    each root against the final matching: its problems are the ones explore found unless something below it
//            explore assumed does not hold (a guess the rules dropped, or a unit met again while it was being compared
//            that has problems after all); then it is compared again, each guess answered by the matching.
// The result does not depend on the order the roots are compared in.
//
// The rules. Where guesses compete, those a unit an annotation pairs proposes come before those only guessed units
// propose, then those the root with the lowest original address reaches, then the order each rule gives:
//   function, vtable and data guesses: one rebuilt object for each original and one original for each rebuilt
//     object, among the guesses that hold; then by (original address, rebuilt address).
//   local statics, in an order of their own: the votes before the comparison (Pairing) fix some; the others are
//     proposed by the references that meet them, and taken by (most referencing units, original address, rebuilt
//     address), one original for each, none reaching over another's start. A read-only static the linker folded
//     (several symbols at its address) also stands for further originals with the same bytes, up to its symbol
//     count.
//   build hashes (`?A0x...@`, `<lambda_...>`): one original hash for each rebuilt hash and back; then by text.
//   FuncInfo: one partner on each side, among those that functions holding (or roots) use; then by address.
// A guess a rule drops does not come back.
#pragma once
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "problem.hpp"

namespace verifier {

class Matching {
 public:
  enum class Kind : u8 { Function, Funclet, Data, Vtable, Local, Hash, FuncInfo };
  enum class Mode : u8 { Explore, Judge };

  Mode mode() const { return mode_; }

  // a local static the votes before the comparison placed: rebuilt `base` stands for original `o_base`
  void fix_local(u64 base, u64 o_base);
  // the original a rebuilt local static stands for: the fixed ones while exploring, the final ones when judging
  std::optional<u64> local_of(u64 base) const;
  bool local_fixed(u64 base) const { return fixed_.count(base) != 0; }
  bool original_fixed(u64 o_base) const;  // a fixed local static stands for it

  // A guess: (o, r) of class `k` holds. Explore: registered (with `reach`, the furthest offset referenced, for a
  // local static), a dependency of the unit being compared, and assumed to hold; a function is queued to be
  // compared (take_queued). Judge: whether the final matching holds it (a guess never explored does not hold).
  bool assume(Kind k, u64 o, u64 r, u64 reach = 0);
  u64 text_id(std::string_view s);                 // a build hash's number, for Kind::Hash
  std::vector<std::pair<u64, u64>> take_queued();  // function candidates registered and not compared yet

  // A comparison unit, (o, r) of class Function, Funclet, Data or Vtable, compared by `body`. Explore: once, its
  // problems kept; met again while it is being compared, it holds (a cycle). Judge: compared again against the final
  // matching (results kept unless they assumed a unit still being compared). Either way the unit being compared
  // depends on it.
  Problems unit(Kind k, u64 o, u64 r, const std::function<Problems()>& body);
  // a root: its problems against the final matching (after solve), `body` comparing it again when needed
  Problems judge_root(Kind k, u64 o, u64 r, const std::function<Problems()>& body);

  struct Rules {
    std::function<int(u64)> folded_locals;            // symbols at a rebuilt local static's address
    std::function<bool(u64, u64, u64)> folded_extra;  // (base, its original, another original): same bytes
  };
  void solve(const Rules& rules);  // explore -> judge
  bool solved() const { return mode_ == Mode::Judge; }
  bool holds(Kind k, u64 o, u64 r) const;

  struct Stats {
    size_t nodes = 0, candidates = 0, accepted = 0, rejudged = 0;
  };
  Stats stats() const;

 private:
  struct Key {
    Kind kind;
    u64 o, r;
    bool operator==(const Key&) const = default;
  };
  struct KeyHash {
    size_t operator()(const Key& k) const {
      return size_t((k.o * 0x9E3779B97F4A7C15ull) ^ (k.r + 0x632BE59BD9B4E019ull + (k.r << 6)) ^ u64(k.kind));
    }
  };
  struct Node {
    Key key;
    bool candidate = false;  // a guess (assume()), kept only when the rules take it
    bool explored = false;   // a unit compared (own and deps known)
    bool in_progress = false;
    bool queued = false;
    bool cycled = false;   // met again while it was being compared (explore assumed it holds)
    bool dropped = false;  // a rule dropped it
    bool ok = false;       // after solve: it holds
    u64 reach = 0;
    Problems own;
    std::vector<u32> deps;
  };
  Mode mode_ = Mode::Explore;
  std::vector<Node> nodes_;
  std::unordered_map<Key, u32, KeyHash> index_;
  std::vector<u32> stack_;  // the units being compared, innermost last
  std::vector<u32> queue_;
  std::vector<char> tainted_;  // after solve: explore's problems for it assumed something that does not hold
  std::unordered_map<u64, u64> fixed_, fixed_o_;  // fixed local statics: base -> original, and back
  std::unordered_map<u64, u64> local_;            // judge: every local static's original (primary)
  std::vector<std::string> texts_;
  std::unordered_map<std::string, u64> text_ids_;
  // judge
  struct Frame {
    u32 id;
    bool truncated;  // assumed a unit still being compared held: its result is this root's only
    bool met;        // met again while it was being compared
    size_t mark;     // here_log_'s size when it started
  };
  std::vector<Frame> jstack_;
  std::unordered_map<u32, Problems> judged_, judged_here_;  // complete results; this root's truncated ones
  std::vector<u32> here_log_;                               // judged_here_'s entries in the order they were made
  size_t rejudged_ = 0;

  u32 node(Kind k, u64 o, u64 r);
  void depend(u32 id);
  void fixed_point(const std::vector<std::vector<u32>>& users);
  void decide_locals(const Rules& rules, const std::vector<std::vector<u32>>& users);
  struct Rank {
    bool guessed = true;  // only guesses propose it (no unit an annotation pairs)
    u64 first_root = ~u64(0);
  };
  std::vector<Rank> rank_;
  void rank(const std::vector<char>& root);
  template <class Less>
  bool one_to_one(std::vector<u32> ids, Less less);
  Problems judge(u32 id, const std::function<Problems()>& body);
};

}  // namespace verifier
