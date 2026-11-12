#include "align.hpp"

#include <algorithm>

namespace verifier {

namespace {

struct Block {
  size_t i, j, k;  // a[i, i+k) equals b[j, j+k)
};
struct Part {
  size_t a0, a1, b0, b1;
};

class Aligner {
 public:
  Aligner(std::span<const u32> a, std::span<const u32> b, size_t max_cost)
      : a_(a), b_(b), max_cost_(max_cost), budget_(long(std::max<size_t>(1 << 22, 64 * (a.size() + b.size())))) {}

  // the equal runs, in order (parts are taken from a stack, not by recursion: a part can split into many)
  std::vector<Block> run() {
    std::vector<Part> todo{{0, a_.size(), 0, b_.size()}};
    while (!todo.empty()) {
      auto [a0, a1, b0, b1] = todo.back();
      todo.pop_back();
      size_t p = 0;
      while (a0 + p < a1 && b0 + p < b1 && a_[a0 + p] == b_[b0 + p]) ++p;
      if (p) blocks_.push_back({a0, b0, p});
      a0 += p;
      b0 += p;
      size_t s = 0;
      while (a0 + s < a1 && b0 + s < b1 && a_[a1 - 1 - s] == b_[b1 - 1 - s]) ++s;
      if (s) blocks_.push_back({a1 - s, b1 - s, s});
      a1 -= s;
      b1 -= s;
      if (a0 == a1 || b0 == b1) continue;
      auto [x, y] = split(a0, a1, b0, b1);
      if (!exact_ && anchored({a0, a1, b0, b1}, todo)) continue;  // too costly for Myers: patience splits it
      if ((x || y) && (a0 + x < a1 || b0 + y < b1)) {             // else no progress: the part is replaced as a whole
        todo.push_back({a0, a0 + x, b0, b0 + y});
        todo.push_back({a0 + x, a1, b0 + y, b1});
      }
    }
    std::sort(blocks_.begin(), blocks_.end(), [](const Block& x, const Block& y) { return x.i < y.i; });
    return std::move(blocks_);
  }

 private:
  std::span<const u32> a_, b_;
  size_t max_cost_;
  long budget_;        // Myers' steps left for the whole alignment
  bool exact_ = true;  // the last split was the middle snake's (else where the search got furthest)
  std::vector<Block> blocks_;
  struct Count {
    u32 na = 0, nb = 0;
    size_t jb = 0;
  };
  std::vector<Count> counts_;  // by element, all zero between calls
  std::vector<u32> touched_;
  std::vector<std::pair<size_t, size_t>> uniq_;
  std::vector<size_t> tops_, prev_;
  std::vector<long> v1_, v2_;

  // Patience diff: the elements found once in each part, in the longest run that is in order in both, align with
  // each other; the parts between them are queued. False when no element is found once in each.
  bool anchored(Part pt, std::vector<Part>& todo) {
    touched_.clear();
    auto at = [&](u32 x) -> Count& {
      if (x >= counts_.size()) counts_.resize(size_t(x) + 1);
      Count& c = counts_[x];
      if (!c.na && !c.nb) touched_.push_back(x);
      return c;
    };
    for (size_t i = pt.a0; i < pt.a1; ++i) ++at(a_[i]).na;
    for (size_t j = pt.b0; j < pt.b1; ++j) {
      Count& c = at(b_[j]);
      ++c.nb;
      c.jb = j;
    }
    uniq_.clear();  // (i, j), by i
    for (size_t i = pt.a0; i < pt.a1; ++i) {
      const Count& c = counts_[a_[i]];
      if (c.na == 1 && c.nb == 1) uniq_.push_back({i, c.jb});
    }
    for (u32 x : touched_) counts_[x] = {};
    if (uniq_.empty()) return false;
    // the longest increasing run of j (patience sorting: each pile's top, and each element's predecessor)
    constexpr size_t NONE = ~size_t(0);
    tops_.clear();
    prev_.resize(uniq_.size());
    for (size_t k = 0; k < uniq_.size(); ++k) {
      auto it = std::lower_bound(tops_.begin(), tops_.end(), uniq_[k].second,
                                 [&](size_t t, size_t j) { return uniq_[t].second < j; });
      prev_[k] = it == tops_.begin() ? NONE : *(it - 1);
      if (it == tops_.end())
        tops_.push_back(k);
      else
        *it = k;
    }
    size_t i = pt.a1, j = pt.b1;
    for (size_t k = tops_.back(); k != NONE; k = prev_[k]) {
      auto [x, y] = uniq_[k];
      blocks_.push_back({x, y, 1});
      todo.push_back({x + 1, i, y + 1, j});
      i = x;
      j = y;
    }
    todo.push_back({pt.a0, i, pt.b0, j});
    return true;
  }

  // Myers' middle snake, after "An O(ND) Difference Algorithm and Its Variations" (1986), section 4b: the forward and
  // the reverse search take a step each in turn until their paths overlap, which splits the part in two. Where to
  // split a[a0, a1) and b[b0, b1) (both not empty, their first and last elements different), relative to a0 and b0:
  // strictly inside, so both halves are smaller; {0, 0} once the budget is spent (the part is then replaced whole).
  std::pair<size_t, size_t> split(size_t a0, size_t a1, size_t b0, size_t b1) {
    exact_ = false;
    if (budget_ <= 0) return {0, 0};
    long n = long(a1 - a0), m = long(b1 - b0);
    long max_d = (n + m + 1) / 2;
    long lim = std::min(max_d, long(max_cost_) + 1);
    long off = lim + 1, len = 2 * lim + 3;
    v1_.assign(size_t(len), -1);
    v2_.assign(size_t(len), -1);
    v1_[size_t(off + 1)] = 0;
    v2_[size_t(off + 1)] = 0;
    long delta = n - m;
    bool front = delta & 1;  // the forward path meets the reverse one on an odd difference
    long k1start = 0, k1end = 0, k2start = 0, k2end = 0;
    auto A = [&](long x) { return a_[a0 + size_t(x)]; };
    auto B = [&](long y) { return b_[b0 + size_t(y)]; };
    long best_x = 0, best_y = 0;  // the forward point furthest along, for a part that costs too much
    for (long d = 0; d < max_d && d < lim && budget_ > 0; ++d) {
      budget_ -= 2 * d + 2;
      for (long k1 = -d + k1start; k1 <= d - k1end; k1 += 2) {
        long ko = off + k1;
        long x1 = (k1 == -d || (k1 != d && v1_[size_t(ko - 1)] < v1_[size_t(ko + 1)])) ? v1_[size_t(ko + 1)]
                                                                                       : v1_[size_t(ko - 1)] + 1;
        long y1 = x1 - k1;
        while (x1 < n && y1 < m && A(x1) == B(y1)) ++x1, ++y1;
        v1_[size_t(ko)] = x1;
        if (x1 > n) {
          k1end += 2;
        } else if (y1 > m) {
          k1start += 2;
        } else {
          if (x1 + y1 > best_x + best_y) best_x = x1, best_y = y1;
          if (front) {
            long k2o = off + delta - k1;
            if (k2o >= 0 && k2o < len && v2_[size_t(k2o)] != -1 && x1 >= n - v2_[size_t(k2o)])
              return exact_ = true, std::pair{size_t(x1), size_t(y1)};
          }
        }
      }
      for (long k2 = -d + k2start; k2 <= d - k2end; k2 += 2) {
        long ko = off + k2;
        long x2 = (k2 == -d || (k2 != d && v2_[size_t(ko - 1)] < v2_[size_t(ko + 1)])) ? v2_[size_t(ko + 1)]
                                                                                       : v2_[size_t(ko - 1)] + 1;
        long y2 = x2 - k2;
        while (x2 < n && y2 < m && A(n - x2 - 1) == B(m - y2 - 1)) ++x2, ++y2;
        v2_[size_t(ko)] = x2;
        if (x2 > n) {
          k2end += 2;
        } else if (y2 > m) {
          k2start += 2;
        } else if (!front) {
          long k1o = off + delta - k2;
          if (k1o >= 0 && k1o < len && v1_[size_t(k1o)] != -1) {
            long x1 = v1_[size_t(k1o)], y1 = off + x1 - k1o;
            if (x1 >= n - x2) return exact_ = true, std::pair{size_t(x1), size_t(y1)};
          }
        }
      }
    }
    // too costly: split where the forward search got furthest
    if (best_x + best_y == 0) return {1, 0};
    return {size_t(best_x), size_t(best_y)};
  }
};

}  // namespace

size_t edit_distance(std::span<const u32> a, std::span<const u32> b) {
  long n = long(a.size()), m = long(b.size()), off = n + m + 1;
  std::vector<long> v(size_t(2 * off + 1), 0);
  for (long d = 0;; ++d)
    for (long k = -d; k <= d; k += 2) {
      long x = k == -d || (k != d && v[size_t(off + k - 1)] < v[size_t(off + k + 1)]) ? v[size_t(off + k + 1)]
                                                                                      : v[size_t(off + k - 1)] + 1;
      long y = x - k;
      while (x < n && y < m && a[size_t(x)] == b[size_t(y)]) ++x, ++y;
      v[size_t(off + k)] = x;
      if (x >= n && y >= m) return size_t(d);
    }
}

std::vector<Opcode> align(std::span<const u32> a, std::span<const u32> b, size_t max_cost) {
  std::vector<Block> blocks = Aligner(a, b, max_cost).run();
  std::vector<Opcode> out;
  size_t i = 0, j = 0;
  auto gap = [&](size_t i2, size_t j2) {
    if (i < i2 || j < j2) out.push_back({i < i2 && j < j2 ? 'r' : i < i2 ? 'd' : 'i', i, i2, j, j2});
  };
  for (auto& m : blocks) {
    gap(m.i, m.j);
    if (!out.empty() && out.back().tag == 'e' && out.back().i2 == m.i) {
      out.back().i2 += m.k;
      out.back().j2 += m.k;
    } else {
      out.push_back({'e', m.i, m.i + m.k, m.j, m.j + m.k});
    }
    i = m.i + m.k;
    j = m.j + m.k;
  }
  gap(a.size(), b.size());
  return out;
}

}  // namespace verifier
