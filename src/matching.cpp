#include "matching.hpp"

#include <algorithm>
#include <map>
#include <set>
#include <tuple>

namespace verifier {

namespace {
bool is_unit(Matching::Kind k) {
  return k == Matching::Kind::Function || k == Matching::Kind::Funclet || k == Matching::Kind::Data ||
         k == Matching::Kind::Vtable;
}
}  // namespace

u32 Matching::node(Kind k, u64 o, u64 r) {
  Key key{k, o, r};
  auto [it, fresh] = index_.try_emplace(key, u32(nodes_.size()));
  if (fresh) {
    nodes_.emplace_back();
    nodes_.back().key = key;
  }
  return it->second;
}

void Matching::depend(u32 id) {
  if (mode_ == Mode::Explore && !stack_.empty() && stack_.back() != id) nodes_[stack_.back()].deps.push_back(id);
}

void Matching::fix_local(u64 base, u64 o_base) {
  fixed_[base] = o_base;
  fixed_o_[o_base] = base;
}

bool Matching::original_fixed(u64 o_base) const { return fixed_o_.count(o_base) != 0; }

std::optional<u64> Matching::local_of(u64 base) const {
  const auto& m = mode_ == Mode::Explore ? fixed_ : local_;
  auto it = m.find(base);
  return it == m.end() ? std::nullopt : std::optional<u64>(it->second);
}

u64 Matching::text_id(std::string_view s) {
  auto [it, fresh] = text_ids_.try_emplace(std::string(s), u64(texts_.size()));
  if (fresh) texts_.emplace_back(s);
  return it->second;
}

bool Matching::assume(Kind k, u64 o, u64 r, u64 reach) {
  if (mode_ == Mode::Judge) return holds(k, o, r);
  u32 id = node(k, o, r);
  Node& n = nodes_[id];
  n.candidate = true;
  n.reach = std::max(n.reach, reach);
  if (k == Kind::Function && !n.explored && !n.queued) {
    n.queued = true;
    queue_.push_back(id);
  }
  depend(id);
  return true;
}

std::vector<std::pair<u64, u64>> Matching::take_queued() {
  std::vector<std::pair<u64, u64>> out;
  for (u32 id : queue_)
    if (!nodes_[id].explored) out.emplace_back(nodes_[id].key.o, nodes_[id].key.r);
  queue_.clear();
  return out;
}

bool Matching::holds(Kind k, u64 o, u64 r) const {
  auto it = index_.find(Key{k, o, r});
  if (it == index_.end()) return false;
  const Node& n = nodes_[it->second];
  return n.ok && (!is_unit(k) || n.explored);
}

Problems Matching::unit(Kind k, u64 o, u64 r, const std::function<Problems()>& body) {
  u32 id = node(k, o, r);
  depend(id);
  if (mode_ == Mode::Judge) return judge(id, body);
  if (nodes_[id].explored) return nodes_[id].own;
  if (nodes_[id].in_progress) {  // a cycle: it holds while it is being compared
    nodes_[id].cycled = true;
    return {};
  }
  nodes_[id].in_progress = true;
  stack_.push_back(id);
  Problems p = body();
  stack_.pop_back();
  Node& n = nodes_[id];
  n.in_progress = false;
  n.explored = true;
  n.own = p;
  std::sort(n.deps.begin(), n.deps.end());
  n.deps.erase(std::unique(n.deps.begin(), n.deps.end()), n.deps.end());
  return p;
}

Problems Matching::judge(u32 id, const std::function<Problems()>& body) {
  if (id < tainted_.size() && nodes_[id].explored && !tainted_[id]) return nodes_[id].own;  // explore's stands
  if (auto it = judged_.find(id); it != judged_.end()) return it->second;
  // what holds for this root only (it assumed a unit still being compared) makes what uses it this root's only too
  auto this_root_only = [&](size_t down_to) {
    for (size_t j = jstack_.size(); j-- > down_to;) jstack_[j].truncated = true;
  };
  if (auto it = judged_here_.find(id); it != judged_here_.end()) {
    this_root_only(0);
    return it->second;
  }
  if (nodes_[id].in_progress) {  // a cycle: it holds while it is being compared
    size_t j = jstack_.size();
    while (j > 0 && jstack_[j - 1].id != id) --j;
    this_root_only(j);
    if (j > 0) jstack_[j - 1].met = true;
    return {};
  }
  nodes_[id].in_progress = true;
  jstack_.push_back({id, false, false, here_log_.size()});
  Problems p = body();
  Frame f = jstack_.back();
  jstack_.pop_back();
  nodes_[id].in_progress = false;
  // met again below and found problems after all: what was found assuming it held is taken back
  if (f.met && !p.empty()) {
    for (size_t i = f.mark; i < here_log_.size(); ++i) judged_here_.erase(here_log_[i]);
    here_log_.resize(f.mark);
  }
  if (f.truncated) {
    judged_here_[id] = p;
    here_log_.push_back(id);
  } else {
    judged_[id] = p;
  }
  return p;
}

Problems Matching::judge_root(Kind k, u64 o, u64 r, const std::function<Problems()>& body) {
  judged_here_.clear();
  here_log_.clear();
  u32 id = node(k, o, r);
  if (id < tainted_.size() && nodes_[id].explored && !tainted_[id]) return nodes_[id].own;  // explore's stands
  ++rejudged_;
  return judge(id, body);
}

void Matching::fixed_point(const std::vector<std::vector<u32>>& users) {
  std::vector<u32> work;
  for (u32 i = 0; i < nodes_.size(); ++i) {
    Node& n = nodes_[i];
    n.ok = !n.dropped && (!is_unit(n.key.kind) || (n.explored && n.own.empty()));
    if (!n.ok) work.push_back(i);
  }
  while (!work.empty()) {
    u32 x = work.back();
    work.pop_back();
    for (u32 u : users[x])
      if (nodes_[u].ok) {
        nodes_[u].ok = false;
        work.push_back(u);
      }
  }
}

void Matching::decide_locals(const Rules& rules, const std::vector<std::vector<u32>>& users) {
  std::vector<u32> props;
  for (u32 i = 0; i < nodes_.size(); ++i)
    if (nodes_[i].key.kind == Kind::Local && nodes_[i].candidate) props.push_back(i);
  // most referencing units first, then by address: (votes desc, original asc, rebuilt asc)
  std::sort(props.begin(), props.end(), [&](u32 a, u32 b) {
    const Key &x = nodes_[a].key, &y = nodes_[b].key;
    return std::make_tuple(-i64(users[a].size()), x.o, x.r) < std::make_tuple(-i64(users[b].size()), y.o, y.r);
  });
  std::map<u64, u64> taken;  // original -> rebuilt static
  for (auto& [o, base] : fixed_o_) taken[o] = base;
  std::unordered_map<u64, u64> primary(fixed_.begin(), fixed_.end());
  std::unordered_map<u64, int> count;  // originals each rebuilt static stands for
  for (auto& [base, o] : fixed_) count[base] = 1;
  auto overlaps = [&](u64 o_base, u64 reach, u64 base) {  // another static's original in (o_base, o_base + reach]
    for (auto it = taken.upper_bound(o_base); it != taken.end() && it->first <= o_base + reach; ++it)
      if (it->second != base) return true;
    return false;
  };
  std::vector<u32> rest;
  for (u32 id : props) {
    auto [kind, o, base] = nodes_[id].key;
    if (primary.count(base)) {
      rest.push_back(id);
      continue;
    }
    if (taken.count(o) || overlaps(o, nodes_[id].reach, base)) {
      nodes_[id].dropped = true;
      continue;
    }
    primary[base] = o;
    taken[o] = base;
    count[base] = 1;
  }
  // a folded read-only static's further originals, by address
  std::sort(rest.begin(), rest.end(), [&](u32 a, u32 b) { return nodes_[a].key.o < nodes_[b].key.o; });
  for (u32 id : rest) {
    auto [kind, o, base] = nodes_[id].key;
    if (primary.at(base) == o) continue;
    if (!taken.count(o) && count[base] < rules.folded_locals(base) && rules.folded_extra(base, primary.at(base), o)) {
      taken[o] = base;
      ++count[base];
    } else {
      nodes_[id].dropped = true;
    }
  }
  local_ = std::move(primary);
}

// Where a guess first comes up, for the rules' order: whether a unit an annotation pairs proposes it (not only units
// that are guesses themselves), and the lowest original address of a root whose comparison reaches it.
void Matching::rank(const std::vector<char>& root) {
  rank_.assign(nodes_.size(), Rank{});
  std::vector<u32> roots;
  for (u32 i = 0; i < nodes_.size(); ++i)
    if (root[i] && nodes_[i].explored && !nodes_[i].candidate) roots.push_back(i);
  std::sort(roots.begin(), roots.end(), [&](u32 a, u32 b) {
    return std::tie(nodes_[a].key.o, nodes_[a].key.r) < std::tie(nodes_[b].key.o, nodes_[b].key.r);
  });
  std::vector<char> seen(nodes_.size(), 0), paired(nodes_.size(), 0);
  std::vector<u32> work;
  for (u32 r : roots) {  // in address order: the first root to reach a node is the lowest
    if (!seen[r]) {
      seen[r] = 1;
      rank_[r].first_root = nodes_[r].key.o;
      work.push_back(r);
    }
    while (!work.empty()) {
      u32 x = work.back();
      work.pop_back();
      for (u32 d : nodes_[x].deps)
        if (!seen[d]) {
          seen[d] = 1;
          rank_[d].first_root = nodes_[r].key.o;
          work.push_back(d);
        }
    }
  }
  // the units an annotation pairs: from the roots, not through a guess
  for (u32 r : roots) {
    paired[r] = 1;
    work.push_back(r);
  }
  while (!work.empty()) {
    u32 x = work.back();
    work.pop_back();
    for (u32 d : nodes_[x].deps) {
      rank_[d].guessed = false;
      if (!paired[d] && !nodes_[d].candidate) {
        paired[d] = 1;
        work.push_back(d);
      }
    }
  }
}

// one original for each rebuilt one and back: the guesses taken in order (those an annotated unit proposes first,
// then by the first root reaching them, then `less`), each one whose original or rebuilt side is taken dropped
template <class Less>
bool Matching::one_to_one(std::vector<u32> ids, Less less) {
  std::sort(ids.begin(), ids.end(), [&](u32 a, u32 b) {
    if (rank_[a].guessed != rank_[b].guessed) return rank_[b].guessed;
    if (rank_[a].first_root != rank_[b].first_root) return rank_[a].first_root < rank_[b].first_root;
    return less(a, b);
  });
  std::set<u64> used_o, used_r;
  bool dropped = false;
  for (u32 id : ids) {
    const Key& k = nodes_[id].key;
    if (used_o.count(k.o) || used_r.count(k.r)) {
      nodes_[id].dropped = true;
      dropped = true;
      continue;
    }
    used_o.insert(k.o);
    used_r.insert(k.r);
  }
  return dropped;
}

void Matching::solve(const Rules& rules) {
  std::vector<std::vector<u32>> users(nodes_.size());
  std::vector<char> root(nodes_.size(), 1);  // nothing depends on a root
  for (u32 i = 0; i < nodes_.size(); ++i)
    for (u32 d : nodes_[i].deps) {
      users[d].push_back(i);
      root[d] = 0;
    }
  rank(root);
  decide_locals(rules, users);
  std::vector<u32> hashes;
  for (u32 i = 0; i < nodes_.size(); ++i)
    if (nodes_[i].key.kind == Kind::Hash) hashes.push_back(i);
  one_to_one(hashes, [&](u32 a, u32 b) {
    const Key &x = nodes_[a].key, &y = nodes_[b].key;
    return std::tie(texts_[x.o], texts_[x.r]) < std::tie(texts_[y.o], texts_[y.r]);
  });
  auto by_address = [&](u32 a, u32 b) {
    const Key &x = nodes_[a].key, &y = nodes_[b].key;
    return std::tie(x.o, x.r, x.kind) < std::tie(y.o, y.r, y.kind);
  };
  for (bool changed = true; changed;) {
    fixed_point(users);
    // function, vtable and data guesses that hold
    std::vector<u32> units, fis;
    for (u32 i = 0; i < nodes_.size(); ++i)
      if (nodes_[i].candidate && nodes_[i].ok && is_unit(nodes_[i].key.kind)) units.push_back(i);
    changed = one_to_one(units, by_address);
    // FuncInfo pairs in use (by a root or a unit that holds)
    for (u32 i = 0; i < nodes_.size(); ++i) {
      if (nodes_[i].key.kind != Kind::FuncInfo || nodes_[i].dropped) continue;
      bool used = false;
      for (u32 u : users[i]) used = used || nodes_[u].ok || root[u];
      if (used) fis.push_back(i);
    }
    changed = one_to_one(fis, by_address) || changed;
  }
  mode_ = Mode::Judge;
  // what explore found for a unit stands unless it assumed something that does not hold, anywhere below it: a guess
  // the matching does not hold, or a unit met again while it was being compared (taken to hold) that does not
  std::vector<char> tainted(nodes_.size(), 0);
  std::vector<u32> work;
  for (u32 i = 0; i < nodes_.size(); ++i)
    if ((nodes_[i].candidate || nodes_[i].cycled) && !nodes_[i].ok) {
      tainted[i] = 1;
      work.push_back(i);
    }
  while (!work.empty()) {
    u32 x = work.back();
    work.pop_back();
    for (u32 u : users[x])
      if (!tainted[u]) {
        tainted[u] = 1;
        work.push_back(u);
      }
  }
  tainted_ = std::move(tainted);
}

Matching::Stats Matching::stats() const {
  Stats s;
  s.nodes = nodes_.size();
  for (auto& n : nodes_)
    if (n.candidate) {
      ++s.candidates;
      s.accepted += n.ok;
    }
  s.rejudged = rejudged_;
  return s;
}

}  // namespace verifier
