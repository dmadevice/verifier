#include "names.hpp"

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <unordered_set>

#ifdef _WIN32
#include <windows.h>
#else
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
extern char** environ;
#endif

namespace verifier {

const char* const SCALAR_DD = "`scalar deleting destructor'";

namespace {

bool is_hex_lower(char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }
bool op_char(char c) { return std::string_view("<>=!+-*/%^&|~[],").find(c) != std::string_view::npos; }
bool alpha_(char c) { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_'; }

}  // namespace

std::vector<std::pair<u64, std::string_view>> parse_map(std::string_view text) {
  std::vector<std::pair<u64, std::string_view>> syms;
  for_each_line(text, [&](std::string_view line) {
    std::string_view p[4];   // the first four whitespace-separated fields
    size_t n = 0, i = 0;
    while (n < 4) {
      while (i < line.size() && is_space(line[i])) ++i;
      if (i == line.size()) break;
      size_t j = i;
      while (j < line.size() && !is_space(line[j])) ++j;
      p[n++] = line.substr(i, j - i);
      i = j;
    }
    if (n < 4) return;
    std::string_view a = p[0];
    if (a.size() != 13 || a[4] != ':') return;
    for (int k = 0; k < 13; ++k) if (k != 4 && !is_hex_lower(a[k])) return;
    if (p[2].size() != 16) return;
    for (char c : p[2]) if (!is_hex_lower(c)) return;
    syms.emplace_back(parse_hex(p[2]), p[1]);
  });
  return syms;
}

std::string norm_name(const std::string& in) {
  // drop `__ptr64` (and the whitespace before it)
  std::string s;
  for (size_t i = 0; i < in.size();) {
    size_t j = i;
    while (j < in.size() && is_space(in[j])) ++j;
    if (in.compare(j, 7, "__ptr64") == 0 && (j + 7 == in.size() || !is_word(in[j + 7]))) { i = j + 7; continue; }
    s += in[i++];
  }
  // drop the words `class `, `struct `, `enum `, `union `
  std::string t;
  for (size_t i = 0; i < s.size();) {
    if (i == 0 || !is_word(s[i - 1])) {
      bool hit = false;
      for (const char* kw : {"class ", "struct ", "enum ", "union "}) {
        size_t n = std::strlen(kw);
        if (s.compare(i, n, kw) == 0) { i += n; hit = true; break; }
      }
      if (hit) continue;
    }
    t += s[i++];
  }
  // no whitespace around < > , * &, nor at either end
  std::string u;
  for (size_t i = 0; i < t.size();) {
    size_t j = i;
    while (j < t.size() && is_space(t[j])) ++j;
    if (j < t.size() && std::string_view("<>,*&").find(t[j]) != std::string_view::npos) {
      u += t[j];
      j += 1;
      while (j < t.size() && is_space(t[j])) ++j;
      i = j;
      continue;
    }
    u += t[i++];
  }
  return strip(u);
}

std::string norm_params(const std::string& p) {
  std::string s = norm_name(p);
  // drop namespace and class qualifiers (`word::`)
  std::string q;
  for (size_t i = 0; i < s.size();) {
    if (is_word(s[i]) && (i == 0 || !is_word(s[i - 1]))) {
      size_t j = i;
      while (j < s.size() && is_word(s[j])) ++j;
      if (s.compare(j, 2, "::") == 0) { i = j + 2; continue; }
      q.append(s, i, j - i);
      i = j;
      continue;
    }
    q += s[i++];
  }
  // whitespace runs as one space, none inside the parentheses' ends
  std::string w;
  for (size_t i = 0; i < q.size();) {
    if (is_space(q[i])) { while (i < q.size() && is_space(q[i])) ++i; w += ' '; continue; }
    w += q[i++];
  }
  w = replace_all(replace_all(w, "( ", "("), " )", ")");
  return w == "()" ? "(void)" : w;
}

long param_start(const std::string& s) {
  long depth = 0;
  size_t i = 0, n = s.size();
  while (i < n) {
    if (s.compare(i, 8, "operator") == 0 && (i + 8 == n || !is_word(s[i + 8]))) {   // `operator` then `()` or operator characters
      size_t j = i + 8;
      if (s.compare(j, 2, "()") == 0) j += 2;
      while (j < n && op_char(s[j])) ++j;
      i = j;
      continue;
    }
    char c = s[i];
    if (c == '<') ++depth;
    else if (c == '>') --depth;
    else if (c == '(' && depth <= 0) return long(i);
    ++i;
  }
  return -1;
}

std::string last_token(const std::string& head) {
  // a name ending in `operator()` or `operator<op>`: the leftmost `operator` that ends it
  for (size_t p = head.find("operator"); p != std::string::npos; p = head.find("operator", p + 1)) {
    size_t j = p + 8;
    bool m = false;
    if (head.compare(j, 2, "()") == 0 && j + 2 == head.size()) m = true;
    else if (j < head.size()) {
      size_t k = j;
      while (k < head.size() && op_char(head[k])) ++k;
      m = k > j && k == head.size();
    }
    if (m) {
      std::string before = head.substr(0, p);
      return strip(before).empty() ? head.substr(p) : last_token(before) + head.substr(p);
    }
  }
  int depth = 0, quoted = 0;
  for (long i = long(head.size()) - 1; i >= 0; --i) {
    char c = head[size_t(i)];
    if (c == '>') ++depth;
    else if (c == '<') --depth;
    else if (c == '\'') ++quoted;
    else if (c == '`') --quoted;
    else if (is_space(c) && depth <= 0 && quoted <= 0) {
      std::string before = head.substr(0, size_t(i));
      while (!before.empty() && is_space(before.back())) before.pop_back();
      if (before == "operator" || ends_with(before, " operator") || ends_with(before, "::operator"))
        return last_token(before) + " " + head.substr(size_t(i) + 1);
      return head.substr(size_t(i) + 1);
    }
  }
  return head;
}

// ---- scanners: each gives what the regular expression in its comment gives under std::regex (ECMAScript:
// \s is [ \t\n\v\f\r], \w is [A-Za-z0-9_], `.` is any character but \n and \r) ----

namespace {
bool is_digit(char c) { return c >= '0' && c <= '9'; }
size_t skip_space(std::string_view s, size_t i) { while (i < s.size() && is_space(s[i])) ++i; return i; }
size_t skip_word(std::string_view s, size_t i) { while (i < s.size() && is_word(s[i])) ++i; return i; }
bool at(std::string_view s, size_t i, std::string_view w) { return s.size() >= i && s.substr(i, w.size()) == w; }
// `__\w+` at i: its end, or npos
size_t underscore_word(std::string_view s, size_t i) {
  if (!at(s, i, "__") || i + 2 >= s.size() || !is_word(s[i + 2])) return std::string_view::npos;
  return skip_word(s, i + 2);
}
}  // namespace

// search ([A-Za-z_]\w*)\s*(?:\[[^\]]*\])*\s*(?:=|;|\{): the first identifier followed by array bounds and `=`,
// `;` or `{`. The tail only depends on where the identifier's run of word characters ends, so each run is tried
// once, from its first letter.
std::optional<std::string> global_decl_name(std::string_view s) {
  for (size_t p = 0; p < s.size();) {
    if (!alpha_(s[p])) { ++p; continue; }
    size_t e = skip_word(s, p), i = skip_space(s, e);
    while (i < s.size() && s[i] == '[') {
      size_t close = s.find(']', i + 1);
      if (close == std::string_view::npos) break;
      i = close + 1;
    }
    i = skip_space(s, i);
    if (i < s.size() && (s[i] == '=' || s[i] == ';' || s[i] == '{')) return std::string(s.substr(p, e - p));
    p = e;
  }
  return std::nullopt;
}

// search \b(?:class|struct)\s+(?:__declspec\(\w+\)\s+)?([A-Za-z_][\w:]*)
std::optional<std::string> class_decl_name(std::string_view s) {
  for (size_t p = 0; p < s.size(); ++p) {
    if (p > 0 && is_word(s[p - 1])) continue;
    size_t k = at(s, p, "class") ? p + 5 : at(s, p, "struct") ? p + 6 : 0;
    if (!k) continue;
    size_t i = skip_space(s, k);
    if (i == k) continue;
    auto ident = [&](size_t j) -> std::optional<std::string> {
      if (j >= s.size() || !alpha_(s[j])) return std::nullopt;
      size_t e = j + 1;
      while (e < s.size() && (is_word(s[e]) || s[e] == ':')) ++e;
      return std::string(s.substr(j, e - j));
    };
    if (at(s, i, "__declspec(")) {   // the optional __declspec(\w+)\s+ first; without it, the identifier is `__declspec`
      size_t w = skip_word(s, i + 11);
      if (w > i + 11 && w < s.size() && s[w] == ')') {
        size_t j = skip_space(s, w + 1);
        if (j > w + 1)
          if (auto r = ident(j)) return r;
      }
    }
    if (auto r = ident(i)) return r;
  }
  return std::nullopt;
}

// replace every __declspec\s*\([^)]*\) by " "
std::string strip_declspec(const std::string& s) {
  std::string out;
  size_t done = 0;
  for (size_t p = s.find("__declspec"); p != std::string::npos; p = s.find("__declspec", p + 1)) {
    size_t i = skip_space(s, p + 10);
    if (i >= s.size() || s[i] != '(') continue;
    size_t close = s.find(')', i + 1);
    if (close == std::string::npos) break;   // no later match either
    out.append(s, done, p - done);
    out += ' ';
    done = close + 1;
    p = close;
  }
  if (done == 0) return s;
  out.append(s, done, std::string::npos);
  return out;
}

// For a function returning a function pointer, `R (__cc *__cc f(params))(params)`, the inner `__cc f(params)`
// (from the parameter list's '('):
//   head  \((?:__\w+\s*)?\*                                                          (match_continuous)
//   whole \((?:__\w+\s*)?\*\s*(?:const\s+)?(?:__\w+\s+)?(.+)\)\s*\([^()]*\)[^()]*$  (match_continuous), group 1
// The end of group 1 is fixed: the ')' before the last '(' (whitespace between); the string's only parentheses
// after that '(' are one ')'. Its start is the first position, in the order the backtracking tries them, that
// leaves group 1 non-empty and without line breaks.
std::string fnptr_inner(const std::string& und) {
  if (und.find('*') == std::string::npos || und.find('(') == std::string::npos) return und;
  long i0 = param_start(und);
  if (i0 < 0) return und;
  std::string_view t = std::string_view(und).substr(size_t(i0));
  const size_t npos = std::string_view::npos;
  size_t p = 1;   // t[0] == '('
  if (size_t w = underscore_word(t, 1); w != npos) p = skip_space(t, w);
  if (p >= t.size() || t[p] != '*') return und;
  ++p;
  size_t lp = t.rfind('(');
  if (lp == 0 || lp == npos) return und;
  size_t rp = t.find_first_of("()", lp + 1);
  if (rp == npos || t[rp] != ')' || t.find_first_of("()", rp + 1) != npos) return und;
  size_t c = lp;
  while (c > 0 && is_space(t[c - 1])) --c;
  if (c == 0 || t[c - 1] != ')') return und;
  --c;   // group 1 is [start, c)
  size_t nl = npos;   // the last line break before c
  for (size_t k = c; k-- > 0;) if (t[k] == '\n' || t[k] == '\r') { nl = k; break; }
  auto fits = [&](size_t lo, size_t hi) -> size_t {   // the first of the starts hi, hi-1, ..., lo that fits
    if (hi < lo) return npos;
    size_t s = std::min(hi, c - 1);
    return s >= lo && (nl == npos || s > nl) && s < c ? s : npos;
  };
  auto underscore = [&](size_t r) -> size_t {   // (?:__\w+\s+) at r, then group 1
    size_t w = underscore_word(t, r);
    if (w == npos) return npos;
    size_t e = skip_space(t, w);
    return e > w ? fits(w + 1, e) : npos;
  };
  size_t q = skip_space(t, p), s = npos;
  if (at(t, q, "const")) {
    size_t e = skip_space(t, q + 5);
    if (e > q + 5) {
      s = underscore(e);
      if (s == npos) s = fits(e, e);
      if (s == npos && e > q + 6) s = fits(q + 6, e - 1);
    }
  }
  if (s == npos) s = underscore(q);
  if (s == npos) s = fits(q, q);
  if (s == npos && q > p) s = fits(p, q - 1);
  if (s == npos) return und;
  return std::string(t.substr(s, c - s));
}

// search (?:`(.*)'::`\d+'::)?(`dynamic (?:initializer|atexit destructor) for '.*'')\(void\)$: a dynamic
// initializer or atexit destructor, and the function owning it (group 1) when the object is a local static.
bool dynamic_thunk(const std::string& und, std::optional<std::string>& owner, std::string& name) {
  std::string_view s = und;
  const size_t npos = std::string_view::npos;
  if (s.size() < 8 || s.substr(s.size() - 8) != "''(void)") return false;
  size_t end2 = s.size() - 6;   // group 2 is [D, end2)
  size_t last_nl = npos;
  for (size_t k = 0; k < s.size(); ++k) if (s[k] == '\n' || s[k] == '\r') last_nl = k;
  struct Cand { size_t d, e; };   // a group 2 start, and where group 1 ends when the optional part fits before it
  std::vector<Cand> cands;
  for (size_t d = s.find("`dynamic "); d != npos; d = s.find("`dynamic ", d + 1)) {
    size_t k = d + 9;
    if (at(s, k, "initializer")) k += 11;
    else if (at(s, k, "atexit destructor")) k += 17;
    else continue;
    if (!at(s, k, " for '")) continue;
    k += 6;
    if (k > end2 - 2 || (last_nl != npos && last_nl >= k)) continue;   // `.*` to the closing "''"
    size_t e = npos;
    if (d >= 3 && s.substr(d - 3, 3) == "'::") {   // `'::`<digits>'::` before it
      size_t f = d - 3;
      while (f > 0 && is_digit(s[f - 1])) --f;
      if (f < d - 3 && f >= 4 && s.substr(f - 4, 4) == "'::`") e = f - 4;
    }
    cands.push_back({d, e});
  }
  if (cands.empty()) return false;
  // the leftmost start: a candidate's own, or a '`' that begins `(.*) ending at a candidate's e (no line break
  // in between)
  auto first_tick = [&](size_t e) -> size_t {
    size_t lo = 0;
    for (size_t k = e; k-- > 0;) if (s[k] == '\n' || s[k] == '\r') { lo = k + 1; break; }
    size_t t = s.find('`', lo);
    return t < e ? t : npos;
  };
  size_t best = npos;
  for (auto& c : cands) {
    best = std::min(best, c.d);
    if (c.e != npos) best = std::min(best, first_tick(c.e));
  }
  // at that start the optional part comes first, with the longest group 1
  const Cand* opt = nullptr;
  for (auto& c : cands) {
    if (c.e == npos || c.e <= best || s[best] != '`') continue;
    bool clear = true;
    for (size_t k = best + 1; k < c.e && clear; ++k) clear = s[k] != '\n' && s[k] != '\r';
    if (clear && (!opt || c.e > opt->e)) opt = &c;
  }
  if (opt) {
    owner = std::string(s.substr(best + 1, opt->e - best - 1));
    name = std::string(s.substr(opt->d, end2 - opt->d));
  } else {
    owner.reset();
    name = std::string(s.substr(best, end2 - best));
  }
  return true;
}

std::optional<std::string> definition_name(const std::string& line0) {
  std::string ls = line0;
  size_t a = 0;
  while (a < ls.size() && is_space(ls[a])) ++a;
  if (ls.compare(a, 2, "//") == 0 || ls.compare(a, 1, "#") == 0) return std::nullopt;
  std::string line = ls.find("__declspec") != std::string::npos ? strip_declspec(ls) : ls;
  long i = param_start(line);
  std::string name;
  if (i > 0) {
    std::string head = line.substr(0, size_t(i));
    while (!head.empty() && is_space(head.back())) head.pop_back();
    name = last_token(head);
    size_t k = 0;
    while (k < name.size() && (name[k] == '*' || name[k] == '&')) ++k;
    name = name.substr(k);
  }
  if (!name.empty() && (alpha_(name[0]) || name[0] == '~')) return name;
  return std::nullopt;
}

static std::optional<std::string> static_owner_c(const std::string& und) {
  // `` `name'::`<digits>'::`` (an extern "C" function's local static)
  for (size_t p = und.find('`'); p != std::string::npos; p = und.find('`', p + 1)) {
    size_t j = p + 1;
    if (j >= und.size() || !alpha_(und[j])) continue;
    size_t k = j;
    while (k < und.size() && is_word(und[k])) ++k;
    if (und.compare(k, 4, "'::`") != 0) continue;
    size_t d = k + 4, e = d;
    while (e < und.size() && und[e] >= '0' && und[e] <= '9') ++e;
    if (e == d || und.compare(e, 3, "'::") != 0) continue;
    return und.substr(j, k - j);
  }
  return std::nullopt;
}

std::string_view last_components(std::string_view q, int n) {
  size_t at[2] = {std::string_view::npos, std::string_view::npos};   // the last two occurrences
  for (size_t p = q.find("::"); p != std::string_view::npos; p = q.find("::", p + 2)) { at[1] = at[0]; at[0] = p; }
  size_t p = at[n - 1];
  return p == std::string_view::npos ? q : q.substr(p + 2);
}

std::string static_owner(const std::string& und) {
  auto c = static_owner_c(und);
  return c ? *c : qualified(und);
}

std::string signature(const std::string& und0) {
  std::string und = fnptr_inner(und0);
  long i = param_start(und);
  if (i < 0) return "";
  int depth = 0;
  for (size_t k = size_t(i); k < und.size(); ++k) {
    if (und[k] == '(') ++depth;
    else if (und[k] == ')') {
      --depth;
      if (depth == 0) return norm_params(und.substr(size_t(i), k + 1 - size_t(i)));
    }
  }
  return "";
}

static std::string qualified_uncached(const std::string& und) {
  if (und.find("deleting destructor'") != std::string::npos) {
    // DELETING_DD.search: (\S*)(`(?:scalar|vector) deleting destructor'(?:`adjustor\{\d+\}'|`vtordisp\{\d+,\d+\}')?)
    size_t best = std::string::npos;
    for (const char* k : {"`scalar deleting destructor'", "`vector deleting destructor'"}) {
      size_t p = und.find(k);
      if (p < best) best = p;
    }
    if (best != std::string::npos) {
      // greedy \S*: within the run of non-spaces holding the first occurrence, the last occurrence is taken
      size_t run_end = best;
      while (run_end < und.size() && !is_space(und[run_end])) ++run_end;
      size_t p = best;
      for (const char* k : {"`scalar deleting destructor'", "`vector deleting destructor'"})
        for (size_t q = und.find(k, best); q != std::string::npos && q + std::strlen(k) <= run_end; q = und.find(k, q + 1))
          p = std::max(p, q);
      size_t e = p + std::strlen("`scalar deleting destructor'");
      auto digits = [&](size_t& x) { size_t y = x; while (y < und.size() && und[y] >= '0' && und[y] <= '9') ++y; bool ok = y > x; x = y; return ok; };
      if (und.compare(e, 10, "`adjustor{") == 0) {
        size_t x = e + 10;
        if (digits(x) && und.compare(x, 2, "}'") == 0) e = x + 2;
      } else if (und.compare(e, 10, "`vtordisp{") == 0) {
        size_t x = e + 10;
        if (digits(x) && x < und.size() && und[x] == ',') {
          ++x;
          if (digits(x) && und.compare(x, 2, "}'") == 0) e = x + 2;
        }
      }
      return norm_name(last_token(und.substr(0, p)) + und.substr(p, e - p));
    }
  }
  if (und.find("`dynamic ") != std::string::npos) {
    std::optional<std::string> owner;
    std::string name;
    if (dynamic_thunk(und, owner, name))
      return norm_name((!owner || owner->empty() ? "" : static_owner(*owner) + "::") + name);
  }
  std::string u = fnptr_inner(und);
  long i = param_start(u);
  std::string head = i >= 0 ? u.substr(0, size_t(i)) : u;
  while (!head.empty() && is_space(head.back())) head.pop_back();
  return norm_name(last_token(head));
}

std::string qualified(const std::string& und) {
  static std::unordered_map<std::string, std::string> memo;
  auto it = memo.find(und);
  if (it != memo.end()) return it->second;
  return memo.emplace(und, qualified_uncached(und)).first->second;
}

size_t local_static_match(std::string_view d) {
  // a local static or its guard: `?<name>@?<scope>??<owner>` or `?$S<n>@?<scope>??<owner>`, scope a digit or [A-P]+@
  size_t n = d.size(), i = 0;
  if (i >= n || d[i] != '?') return 0;
  ++i;
  size_t j = std::string::npos;
  if (d.compare(i, 2, "$S") == 0) {
    size_t k = i + 2;
    while (k < n && d[k] >= '0' && d[k] <= '9') ++k;
    if (k > i + 2 && k < n && d[k] == '@') j = k;
  }
  if (j == std::string::npos) {
    if (i < n && d[i] != '@' && d[i] != '?' && d[i] != '$') {
      size_t k = i + 1;
      while (k < n && d[k] != '@') ++k;
      if (k < n) j = k;
    }
  }
  if (j == std::string::npos || d.compare(j, 2, "@?") != 0) return 0;
  size_t k = j + 2;
  if (k < n && d[k] >= '0' && d[k] <= '9' && d.compare(k + 1, 2, "??") == 0) return k + 3;
  size_t m = k;
  while (m < n && d[m] >= 'A' && d[m] <= 'P') ++m;
  if (m > k && m < n && d[m] == '@' && d.compare(m + 1, 2, "??") == 0) return m + 3;
  return 0;
}

// --- running undname ----------------------------------------------------------------------------------------

namespace {

std::string run_capture(const std::string& exe, const std::vector<std::string>& args) {
#ifdef _WIN32
  // subprocess.list2cmdline quoting (names never hold spaces or quotes, so this is plain joining in practice)
  auto quote = [](const std::string& a) {
    if (!a.empty() && a.find_first_of(" \t\"") == std::string::npos) return a;
    std::string r = "\"";
    size_t bs = 0;
    for (char c : a) {
      if (c == '\\') { ++bs; continue; }
      if (c == '"') { r.append(bs * 2 + 1, '\\'); r += '"'; bs = 0; continue; }
      r.append(bs, '\\'); bs = 0; r += c;
    }
    r.append(bs * 2, '\\');
    return r + "\"";
  };
  std::string cmd = quote(exe);
  for (auto& a : args) cmd += " " + quote(a);
  SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
  HANDLE rd, wr;
  if (!CreatePipe(&rd, &wr, &sa, 0)) throw std::runtime_error("CreatePipe failed");
  SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
  STARTUPINFOA si{};
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdOutput = wr;
  si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
  si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
  PROCESS_INFORMATION pi{};
  std::vector<char> buf(cmd.begin(), cmd.end());
  buf.push_back('\0');
  if (!CreateProcessA(nullptr, buf.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
    CloseHandle(rd); CloseHandle(wr);
    throw std::runtime_error("cannot run " + exe);
  }
  CloseHandle(wr);
  std::string out;
  char tmp[65536];
  DWORD got;
  while (ReadFile(rd, tmp, sizeof tmp, &got, nullptr) && got) out.append(tmp, got);
  CloseHandle(rd);
  WaitForSingleObject(pi.hProcess, INFINITE);
  CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
  return out;
#else
  int fd[2];
  if (pipe(fd) != 0) throw std::runtime_error("pipe failed");
  posix_spawn_file_actions_t fa;
  posix_spawn_file_actions_init(&fa);
  posix_spawn_file_actions_adddup2(&fa, fd[1], 1);
  posix_spawn_file_actions_addclose(&fa, fd[0]);
  std::vector<char*> argv;
  argv.push_back(const_cast<char*>(exe.c_str()));
  for (auto& a : args) argv.push_back(const_cast<char*>(a.c_str()));
  argv.push_back(nullptr);
  pid_t pid;
  int rc = posix_spawn(&pid, exe.c_str(), &fa, nullptr, argv.data(), environ);
  posix_spawn_file_actions_destroy(&fa);
  close(fd[1]);
  if (rc != 0) { close(fd[0]); throw std::runtime_error("cannot run " + exe); }
  std::string out;
  char tmp[65536];
  ssize_t got;
  while ((got = read(fd[0], tmp, sizeof tmp)) > 0) out.append(tmp, size_t(got));
  close(fd[0]);
  int st;
  waitpid(pid, &st, 0);
  return out;
#endif
}

// undname's output: `Undecoration of :- "<decorated>"` then `is :- "<undecorated>"`, for each name
void parse_undname(const std::string& out, std::unordered_map<std::string, std::string>& res) {
  const std::string a = "Undecoration of :- \"", b = "is :- \"";
  size_t p = 0;
  for (;;) {
    size_t s = out.find(a, p);
    if (s == std::string::npos) return;
    size_t ns = s + a.size();
    // lazy (.*?) then "\s*is :- " : the first '"' followed by whitespace and `is :- "`
    size_t q = ns, found = std::string::npos, vs = 0;
    while ((q = out.find('"', q)) != std::string::npos) {
      size_t w = q + 1;
      while (w < out.size() && is_space(out[w])) ++w;
      if (out.compare(w, b.size(), b) == 0) { found = q; vs = w + b.size(); break; }
      ++q;
    }
    if (found == std::string::npos) return;
    size_t ve = out.find('"', vs);
    if (ve == std::string::npos) return;
    res[out.substr(ns, found - ns)] = out.substr(vs, ve - vs);
    p = ve + 1;
  }
}

}  // namespace

std::unordered_map<std::string, std::string> undecorate(const std::vector<std::string>& names, const std::string& undname) {
  std::vector<std::string> todo;
  for (auto& n : names) if (!n.empty() && n[0] == '?') todo.push_back(n);
  std::sort(todo.begin(), todo.end());
  todo.erase(std::unique(todo.begin(), todo.end()), todo.end());
  // batches of at most 200 names and 30000 characters (the Windows command line holds 32767)
  std::vector<std::vector<std::string>> batches;
  std::vector<std::string> cur;
  size_t size = 0;
  for (auto& n : todo) {
    if (!cur.empty() && (cur.size() == 200 || size + n.size() > 30000)) { batches.push_back(cur); cur.clear(); size = 0; }
    cur.push_back(n);
    size += n.size() + 1;
  }
  if (!cur.empty()) batches.push_back(cur);
  std::unordered_map<std::string, std::string> res;
  for (auto& b : batches) parse_undname(run_capture(undname, b), res);
  return res;
}

// --- the name cache -----------------------------------------------------------------------------------------
// A binary file, used in place (little-endian u32s):
//   "verifier-names 2\n" key "\n", zero-padded to a multiple of 8
//   nstrings, nentries, entry_slots, string_slots     (slots: powers of two)
//   string_end[nstrings]       string i is text[string_end[i-1], string_end[i])
//   entries[nentries][8]       decorated, has_und, und, qualified, signature, owner, and the qualified name's last
//                              one and two components (string ids; has_und 0/1), in the map's order
//   entry_index[entry_slots]   entry + 1 at name_hash(decorated), linear probing (0: empty)
//   string_index[string_slots] string id + 1 at name_hash(string)
//   text
// Every string is stored once, so equal strings have equal ids: the name tables compare ids. The entries are in
// the order the build's map had them, so the next build's names are found by reading on (the index for the rest).

namespace {

constexpr const char* NAMES_MAGIC = "verifier-names 2\n";

u64 name_hash(std::string_view s) {   // stable across runs (the file's indexes are built with it)
  u64 h = 0x9E3779B97F4A7C15ull ^ s.size();
  size_t i = 0;
  for (; i + 8 <= s.size(); i += 8) {
    u64 w;
    std::memcpy(&w, s.data() + i, 8);
    h = (h ^ w) * 0xbf58476d1ce4e5b9ull;
    h ^= h >> 31;
  }
  u64 w = 0;
  if (i < s.size()) std::memcpy(&w, s.data() + i, s.size() - i);
  h = (h ^ w) * 0x94d049bb133111ebull;
  return h ^ (h >> 29);
}

constexpr size_t ROW = 8;   // u32s per entry

u32 slots_for(size_t n) {
  u32 c = 16;
  while (c < 2 * n) c *= 2;
  return c;
}

}  // namespace

NameCache::NameCache(std::string path, std::string key, std::string undname)
    : path_(std::move(path)), key_(std::move(key)), undname_(std::move(undname)) {
  if (path_.empty() || !file_exists(path_)) return;
  try {
    file_ = read_file(path_);
    std::string head = std::string(NAMES_MAGIC) + key_ + "\n";
    size_t at = (head.size() + 7) / 8 * 8;
    if (file_.size() < at + 16 || file_.compare(0, head.size(), head) != 0) { file_.clear(); return; }
    const u32* h = reinterpret_cast<const u32*>(file_.data() + at);
    u64 ns = h[0], ne = h[1], es = h[2], ss = h[3];
    u64 words = 4 + ns + ROW * ne + es + ss;
    if ((es & (es - 1)) || (ss & (ss - 1)) || !es || !ss || file_.size() < at + 4 * words) { file_.clear(); return; }
    str_end_ = h + 4;
    ent_ = str_end_ + ns;
    eidx_ = ent_ + ROW * ne;
    sidx_ = eidx_ + es;
    text_ = file_.data() + at + 4 * words;
    u64 text_size = file_.size() - at - 4 * words;
    if (ns && str_end_[ns - 1] != text_size) { file_.clear(); return; }
    for (u64 i = 0; i < ns; ++i)
      if (str_end_[i] > text_size || (i && str_end_[i] < str_end_[i - 1])) { file_.clear(); return; }
    for (u64 i = 0; i < ROW * ne; ++i)
      if ((i % ROW == 1 ? ent_[i] > 1 : ent_[i] >= ns)) { file_.clear(); return; }
    for (u64 i = 0; i < es; ++i) if (eidx_[i] > ne) { file_.clear(); return; }
    for (u64 i = 0; i < ss; ++i) if (sidx_[i] > ns) { file_.clear(); return; }
    nstr_ = u32(ns);
    nent_ = u32(ne);
    eslots_ = u32(es);
    sslots_ = u32(ss);
    file_info_.resize(nent_);
    loaded_from_file_ = true;
  } catch (...) {
    file_.clear();
  }
}

std::string_view NameCache::text(u32 id) const {
  if (id < nstr_) {
    u32 b = id ? str_end_[id - 1] : 0;
    return std::string_view(text_ + b, str_end_[id] - b);
  }
  return new_text_[id - nstr_];
}

std::optional<u32> NameCache::find_string(std::string_view s) const {
  if (sslots_) {
    for (u32 i = u32(name_hash(s)) & (sslots_ - 1);; i = (i + 1) & (sslots_ - 1)) {
      u32 v = sidx_[i];
      if (!v) break;
      if (text(v - 1) == s) return v - 1;
    }
  }
  auto it = new_ids_.find(s);
  if (it != new_ids_.end()) return it->second;
  return std::nullopt;
}

u32 NameCache::intern(std::string s) {
  if (auto id = find_string(s)) return *id;
  u32 id = nstr_ + u32(new_text_.size());
  std::string_view v = owned_.emplace_back(std::move(s));
  new_text_.push_back(v);
  new_ids_.emplace(v, id);
  return id;
}

std::optional<u32> NameCache::id_of(std::string_view s) const { return find_string(s); }

long NameCache::find_entry(std::string_view d) const {
  if (!eslots_) return -1;
  for (u32 i = u32(name_hash(d)) & (eslots_ - 1);; i = (i + 1) & (eslots_ - 1)) {
    u32 v = eidx_[i];
    if (!v) return -1;
    if (text(ent_[ROW * size_t(v - 1)]) == d) return long(v - 1);
  }
}

const NameInfo* NameCache::file_entry(u32 k) const {
  NameInfo& ni = file_info_[k];
  if (!ni.set) {
    const u32* e = ent_ + ROW * size_t(k);
    ni = NameInfo{true, e[1] != 0, text(e[0]), text(e[2]), text(e[3]), text(e[4]), text(e[5]), e[3], e[4], e[5], e[6], e[7]};
  }
  return &ni;
}

const NameInfo* NameCache::find(std::string_view d) const {
  long k = find_entry(d);
  if (k >= 0) return file_entry(u32(k));
  auto it = new_entries_.find(d);
  return it == new_entries_.end() ? nullptr : &it->second;
}

std::vector<const NameInfo*> NameCache::load(const std::vector<std::string_view>& decorated) {
  std::vector<const NameInfo*> infos(decorated.size());
  std::vector<std::string> missing;
  u32 next = 0;   // the file entry after the last one found: usually the next name's
  for (size_t i = 0; i < decorated.size(); ++i) {
    long k = next < nent_ && text(ent_[ROW * size_t(next)]) == decorated[i] ? long(next) : find_entry(decorated[i]);
    if (k < 0) { missing.emplace_back(decorated[i]); continue; }
    infos[i] = file_entry(u32(k));
    next = u32(k) + 1;
  }
  if (!missing.empty()) {
    std::sort(missing.begin(), missing.end());
    missing.erase(std::unique(missing.begin(), missing.end()), missing.end());
    auto und = undecorate(missing, undname_);
    for (auto& d : missing) {
      auto it = und.find(d);
      const std::string& u = it == und.end() ? d : it->second;
      std::string q = qualified(u);
      u32 l1 = intern(std::string(last_components(q, 1))), l2 = intern(std::string(last_components(q, 2)));
      u32 dec = intern(d), un = intern(it == und.end() ? "" : it->second), qi = intern(std::move(q)), sg = intern(signature(u)),
          ow = intern(static_owner(u));
      new_entries_.emplace(text(dec), NameInfo{true, it != und.end(), text(dec), text(un), text(qi), text(sg), text(ow), qi, sg, ow, l1, l2});
    }
    for (size_t i = 0; i < decorated.size(); ++i)
      if (!infos[i]) infos[i] = find(decorated[i]);
  }
  used_.clear();
  used_.reserve(infos.size());
  for (auto* ni : infos) used_.push_back(ni->decorated);
  return infos;
}

void NameCache::save() {
  if (path_.empty()) return;
  std::vector<std::string_view> names;   // in map order, each once
  {
    std::unordered_set<std::string_view, SvHash> seen;
    seen.reserve(used_.size());
    for (auto n : used_) if (seen.insert(n).second) names.push_back(n);
  }
  bool in_order = loaded_from_file_ && new_entries_.empty() && names.size() == nent_;
  for (size_t k = 0; in_order && k < names.size(); ++k) in_order = text(ent_[ROW * k]) == names[k];
  if (in_order) return;   // the file holds exactly these, in this order
  // the strings of these names, each once
  std::vector<std::string_view> strs;
  std::unordered_map<std::string_view, u32, SvHash> ids;
  auto id = [&](std::string_view s) {
    auto [it, fresh] = ids.emplace(s, u32(strs.size()));
    if (fresh) strs.push_back(s);
    return it->second;
  };
  std::vector<u32> ent;
  ent.reserve(ROW * names.size());
  for (auto& n : names) {
    const NameInfo& ni = *find(n);
    for (u32 v : {id(ni.decorated), u32(ni.has_und), id(ni.und), id(ni.qualified), id(ni.signature), id(ni.owner),
                  id(text(ni.last1_id)), id(text(ni.last2_id))})
      ent.push_back(v);
  }
  u32 es = slots_for(names.size()), ss = slots_for(strs.size());
  std::vector<u32> eidx(es), sidx(ss), ends;
  for (size_t k = 0; k < names.size(); ++k) {
    u32 i = u32(name_hash(names[k])) & (es - 1);
    while (eidx[i]) i = (i + 1) & (es - 1);
    eidx[i] = u32(k + 1);
  }
  u64 total = 0;
  for (size_t k = 0; k < strs.size(); ++k) {
    u32 i = u32(name_hash(strs[k])) & (ss - 1);
    while (sidx[i]) i = (i + 1) & (ss - 1);
    sidx[i] = u32(k + 1);
    total += strs[k].size();
    if (total > 0xffffffffu) return;   // too large for the format: no cache
    ends.push_back(u32(total));
  }
  std::string out = std::string(NAMES_MAGIC) + key_ + "\n";
  out.resize((out.size() + 7) / 8 * 8, '\0');
  auto put = [&](const std::vector<u32>& v) { out.append(reinterpret_cast<const char*>(v.data()), 4 * v.size()); };
  put({u32(strs.size()), u32(names.size()), es, ss});
  put(ends);
  put(ent);
  put(eidx);
  put(sidx);
  for (auto& s : strs) out += s;
  std::string tmp = path_ + ".tmp";
  {
    std::ofstream f(tmp, std::ios::binary);
    if (!f) return;
    f.write(out.data(), std::streamsize(out.size()));
    if (!f) return;
  }
  std::error_code ec;
  std::filesystem::rename(tmp, path_, ec);   // readers see the old file or the new one
}

}  // namespace verifier
