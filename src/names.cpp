#include "names.hpp"

#include <algorithm>
#include <cstring>

namespace verifier {

const char* const SCALAR_DD = "`scalar deleting destructor'";

namespace {

bool is_hex_lower(char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }
bool op_char(char c) { return std::string_view("<>=!+-*/%^&|~[],").find(c) != std::string_view::npos; }
bool alpha_(char c) { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_'; }
size_t skip_space(std::string_view s, size_t i) {
  while (i < s.size() && is_space(s[i])) ++i;
  return i;
}
size_t skip_word(std::string_view s, size_t i) {
  while (i < s.size() && is_word(s[i])) ++i;
  return i;
}
size_t skip_digits(std::string_view s, size_t i) {
  while (i < s.size() && is_digit(s[i])) ++i;
  return i;
}
bool at(std::string_view s, size_t i, std::string_view w) { return s.size() >= i && s.substr(i, w.size()) == w; }
// `__\w+` at i: its end, or npos
size_t underscore_word(std::string_view s, size_t i) {
  if (!at(s, i, "__") || i + 2 >= s.size() || !is_word(s[i + 2])) return std::string_view::npos;
  return skip_word(s, i + 2);
}

}  // namespace

std::vector<std::pair<u64, std::string_view>> parse_map(std::string_view text) {
  std::vector<std::pair<u64, std::string_view>> syms;
  for_each_line(text, [&](std::string_view line) {
    std::string_view p[4];  // the first four whitespace-separated fields
    size_t n = 0, i = 0;
    while (n < 4) {
      i = skip_space(line, i);
      if (i == line.size()) break;
      size_t j = i;
      while (j < line.size() && !is_space(line[j])) ++j;
      p[n++] = line.substr(i, j - i);
      i = j;
    }
    if (n < 4) return;
    std::string_view a = p[0];
    if (a.size() != 13 || a[4] != ':') return;
    for (int k = 0; k < 13; ++k)
      if (k != 4 && !is_hex_lower(a[k])) return;
    if (p[2].size() != 16) return;
    for (char c : p[2])
      if (!is_hex_lower(c)) return;
    syms.emplace_back(parse_hex(p[2]), p[1]);
  });
  return syms;
}

std::string norm_name(const std::string& in) {
  // drop `__ptr64` (and the whitespace before it)
  std::string s;
  for (size_t i = 0; i < in.size();) {
    size_t j = skip_space(in, i);
    if (in.compare(j, 7, "__ptr64") == 0 && (j + 7 == in.size() || !is_word(in[j + 7]))) {
      i = j + 7;
      continue;
    }
    s += in[i++];
  }
  // drop the words `class `, `struct `, `enum `, `union `
  std::string t;
  for (size_t i = 0; i < s.size();) {
    if (i == 0 || !is_word(s[i - 1])) {
      bool hit = false;
      for (const char* kw : {"class ", "struct ", "enum ", "union "}) {
        size_t n = std::strlen(kw);
        if (s.compare(i, n, kw) == 0) {
          i += n;
          hit = true;
          break;
        }
      }
      if (hit) continue;
    }
    t += s[i++];
  }
  // no whitespace around < > , * &, nor at either end
  std::string u;
  for (size_t i = 0; i < t.size();) {
    size_t j = skip_space(t, i);
    if (j < t.size() && std::string_view("<>,*&").find(t[j]) != std::string_view::npos) {
      u += t[j];
      i = skip_space(t, j + 1);
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
      size_t j = skip_word(s, i);
      if (s.compare(j, 2, "::") == 0) {
        i = j + 2;
        continue;
      }
      q.append(s, i, j - i);
      i = j;
      continue;
    }
    q += s[i++];
  }
  // whitespace runs as one space, none inside the parentheses' ends
  std::string w;
  for (size_t i = 0; i < q.size();) {
    if (is_space(q[i])) {
      i = skip_space(q, i);
      w += ' ';
      continue;
    }
    w += q[i++];
  }
  w = replace_all(replace_all(w, "( ", "("), " )", ")");
  return w == "()" ? "(void)" : w;
}

long param_start(const std::string& s) {
  long depth = 0;
  size_t i = 0, n = s.size();
  while (i < n) {
    if (s.compare(i, 8, "operator") == 0 &&
        (i + 8 == n || !is_word(s[i + 8]))) {  // `operator` then `()` or operator characters
      size_t j = i + 8;
      if (s.compare(j, 2, "()") == 0) j += 2;
      while (j < n && op_char(s[j])) ++j;
      i = j;
      continue;
    }
    char c = s[i];
    if (c == '<')
      ++depth;
    else if (c == '>')
      --depth;
    else if (c == '(' && depth <= 0)
      return long(i);
    ++i;
  }
  return -1;
}

std::string last_token(const std::string& head) {
  // a name ending in `operator()` or `operator<op>`: the leftmost `operator` that ends it
  for (size_t p = head.find("operator"); p != std::string::npos; p = head.find("operator", p + 1)) {
    size_t j = p + 8;
    bool m = false;
    if (head.compare(j, 2, "()") == 0 && j + 2 == head.size())
      m = true;
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
    if (c == '>')
      ++depth;
    else if (c == '<')
      --depth;
    else if (c == '\'')
      ++quoted;
    else if (c == '`')
      --quoted;
    else if (is_space(c) && depth <= 0 && quoted <= 0) {
      std::string before = rstrip(std::string_view(head).substr(0, size_t(i)));
      if (before == "operator" || ends_with(before, " operator") || ends_with(before, "::operator"))
        return last_token(before) + " " + head.substr(size_t(i) + 1);
      return head.substr(size_t(i) + 1);
    }
  }
  return head;
}

// ---- scanners: each gives what the regular expression in its comment gives under std::regex (ECMAScript:
// \s is [ \t\n\v\f\r], \w is [A-Za-z0-9_], `.` is any character but \n and \r) ----

// search ([A-Za-z_]\w*)\s*(?:\[[^\]]*\])*\s*(?:=|;|\{): the first identifier followed by array bounds and `=`,
// `;` or `{`. The tail only depends on where the identifier's run of word characters ends, so each run is tried
// once, from its first letter.
std::optional<std::string> global_decl_name(std::string_view s) {
  for (size_t p = 0; p < s.size();) {
    if (!alpha_(s[p])) {
      ++p;
      continue;
    }
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
    if (at(s, i, "__declspec(")) {  // the optional __declspec(\w+)\s+ first; without it, the identifier is `__declspec`
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
    if (close == std::string::npos) break;  // no later match either
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
  size_t p = 1;  // t[0] == '('
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
  --c;               // group 1 is [start, c)
  size_t nl = npos;  // the last line break before c
  for (size_t k = c; k-- > 0;)
    if (t[k] == '\n' || t[k] == '\r') {
      nl = k;
      break;
    }
  auto fits = [&](size_t lo, size_t hi) -> size_t {  // the first of the starts hi, hi-1, ..., lo that fits
    if (hi < lo) return npos;
    size_t s = std::min(hi, c - 1);
    return s >= lo && (nl == npos || s > nl) && s < c ? s : npos;
  };
  auto underscore = [&](size_t r) -> size_t {  // (?:__\w+\s+) at r, then group 1
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
  size_t end2 = s.size() - 6;  // group 2 is [D, end2)
  size_t last_nl = npos;
  for (size_t k = 0; k < s.size(); ++k)
    if (s[k] == '\n' || s[k] == '\r') last_nl = k;
  struct Cand {
    size_t d, e;
  };  // a group 2 start, and where group 1 ends when the optional part fits before it
  std::vector<Cand> cands;
  for (size_t d = s.find("`dynamic "); d != npos; d = s.find("`dynamic ", d + 1)) {
    size_t k = d + 9;
    if (at(s, k, "initializer"))
      k += 11;
    else if (at(s, k, "atexit destructor"))
      k += 17;
    else
      continue;
    if (!at(s, k, " for '")) continue;
    k += 6;
    if (k > end2 - 2 || (last_nl != npos && last_nl >= k)) continue;  // `.*` to the closing "''"
    size_t e = npos;
    if (d >= 3 && s.substr(d - 3, 3) == "'::") {  // `'::`<digits>'::` before it
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
    for (size_t k = e; k-- > 0;)
      if (s[k] == '\n' || s[k] == '\r') {
        lo = k + 1;
        break;
      }
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

std::optional<std::string> definition_name(const std::string& ls) {
  size_t a = skip_space(ls, 0);
  if (ls.compare(a, 2, "//") == 0 || ls.compare(a, 1, "#") == 0) return std::nullopt;
  std::string line = ls.find("__declspec") != std::string::npos ? strip_declspec(ls) : ls;
  long i = param_start(line);
  std::string name;
  if (i > 0) {
    name = last_token(rstrip(std::string_view(line).substr(0, size_t(i))));
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
    size_t k = skip_word(und, j);
    if (und.compare(k, 4, "'::`") != 0) continue;
    size_t d = k + 4, e = skip_digits(und, d);
    if (e == d || und.compare(e, 3, "'::") != 0) continue;
    return und.substr(j, k - j);
  }
  return std::nullopt;
}

std::string_view last_components(std::string_view q, int n) {
  size_t at[2] = {std::string_view::npos, std::string_view::npos};  // the last two occurrences
  for (size_t p = q.find("::"); p != std::string_view::npos; p = q.find("::", p + 2)) {
    at[1] = at[0];
    at[0] = p;
  }
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
    if (und[k] == '(')
      ++depth;
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
        for (size_t q = und.find(k, best); q != std::string::npos && q + std::strlen(k) <= run_end;
             q = und.find(k, q + 1))
          p = std::max(p, q);
      size_t e = p + std::strlen("`scalar deleting destructor'");
      auto digits = [&](size_t& x) {
        size_t y = skip_digits(und, x);
        bool ok = y > x;
        x = y;
        return ok;
      };
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
  return norm_name(last_token(rstrip(i >= 0 ? std::string_view(u).substr(0, size_t(i)) : std::string_view(u))));
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
    size_t k = skip_digits(d, i + 2);
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
  if (k < n && is_digit(d[k]) && d.compare(k + 1, 2, "??") == 0) return k + 3;
  size_t m = k;
  while (m < n && d[m] >= 'A' && d[m] <= 'P') ++m;
  if (m > k && m < n && d[m] == '@' && d.compare(m + 1, 2, "??") == 0) return m + 3;
  return 0;
}

}  // namespace verifier
