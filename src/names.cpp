#include "names.hpp"

#include <algorithm>
#include <cstring>

namespace verifier {

const char* const SCALAR_DD = "`scalar deleting destructor'";

NameKind name_kind(std::string_view d) {
  if (d.starts_with("__real@") || d.starts_with("__xmm@") || d.starts_with("__mask@")) return NameKind::Constant;
  if (d.starts_with("??_C@_1")) return NameKind::WideString;
  if (d.starts_with("??_C@")) return NameKind::String;
  if (d.starts_with("??_R0")) return NameKind::TypeDescriptor;
  if (d.starts_with("_TI")) return NameKind::ThrowInfo;
  if (d.starts_with("??_8")) return NameKind::VbTable;
  if (d.starts_with("??_7")) return NameKind::VfTable;
  if (local_static_match(d)) return NameKind::LocalStatic;
  return NameKind::Other;
}

bool is_literal(NameKind k) { return k == NameKind::Constant || k == NameKind::String || k == NameKind::WideString; }

i64 constant_size(std::string_view d) {
  if (d.starts_with("__real@")) return i64(d.size()) / 2 - 3;
  return name_kind(d) == NameKind::Constant ? 16 : 0;
}

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

// the end of the field starting at i: the first whitespace byte after it (every one is at most ' '), eight bytes at a
// time while none is
size_t field_end(std::string_view s, size_t i) {
  constexpr u64 ones = 0x0101010101010101ull, highs = 0x8080808080808080ull;
  u64 w;
  // nonzero exactly when a byte is below 0x21 (a byte not below it borrows nothing; one of 0x80 or above is masked)
  while (i + 8 <= s.size() && (std::memcpy(&w, s.data() + i, 8), ((w - ones * 0x21) & ~w & highs) == 0)) i += 8;
  while (i < s.size() && !is_space(s[i])) ++i;
  return i;
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
      size_t j = field_end(line, i);
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

std::string deleting_destructor(const std::string& name) {
  size_t p = name.rfind("::");
  return (p == std::string::npos ? name : name.substr(0, p)) + "::" + SCALAR_DD;
}

bool is_norm_name(std::string_view s) {
  for (size_t i = 0; i < s.size(); ++i)
    if (is_space(s[i]) || (s[i] == '_' && s.compare(i, 7, "__ptr64") == 0)) return false;
  return true;
}

std::string norm_name(const std::string& in) {
  // every rule below needs whitespace or `__ptr64` to apply: most names have neither, and are as they are
  if (is_norm_name(in)) return in;
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
  // an anonymous namespace too (undname's text spells some of them by their hash, dropped above as `word::`)
  if (w.find("`anonymous namespace'::") != std::string::npos) w = replace_all(w, "`anonymous namespace'::", "");
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

// A specialisation's constructor or destructor written with the class's arguments, `X<A>::X<A>` or `X<A>::~X<A>`,
// as the map's names have it: by the class's name alone
static std::string plain_structor(std::string name) {
  if (name.empty() || name.back() != '>') return name;
  // the last two components: [cls, sep) "::" [leaf, end), split at the last "::" outside angle brackets
  size_t sep = std::string::npos, cls = 0;
  int depth = 0;
  for (size_t k = name.size(); k-- > 0;) {
    if (name[k] == '>')
      ++depth;
    else if (name[k] == '<')
      --depth;
    else if (depth == 0 && k > 0 && name[k] == ':' && name[k - 1] == ':') {
      if (sep == std::string::npos) {
        sep = k - 1;
      } else {
        cls = k + 1;
        break;
      }
      --k;
    }
  }
  if (sep == std::string::npos) return name;
  size_t leaf = sep + 2 + (name[sep + 2] == '~' ? 1 : 0);
  size_t args = name.find('<', cls);
  if (args == std::string::npos || args >= sep) return name;
  std::string_view n = name;
  // the leaf is the class's name and arguments again
  if (n.substr(leaf) != n.substr(cls, sep - cls)) return name;
  name.resize(leaf + (args - cls));
  return name;
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
  if (!name.empty() && (alpha_(name[0]) || name[0] == '~')) return plain_structor(std::move(name));
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

size_t local_static_match(std::string_view d) {
  // a local static or its guard: `?<name>@?<scope>??<owner>`, `?$S<n>@?<scope>??<owner>`, or in an inline function
  // `??_B?<scope>??<owner>`; scope a digit or [A-P]+@
  size_t n = d.size(), i = 0;
  if (i >= n || d[i] != '?') return 0;
  ++i;
  size_t k = std::string::npos;
  if (d.compare(i, 4, "?_B?") == 0) {
    k = i + 4;
  } else {
    size_t j = std::string::npos;
    if (d.compare(i, 2, "$S") == 0) {
      size_t e = skip_digits(d, i + 2);
      if (e > i + 2 && e < n && d[e] == '@') j = e;
    }
    if (j == std::string::npos) {
      if (i < n && d[i] != '@' && d[i] != '?' && d[i] != '$') {
        size_t e = i + 1;
        while (e < n && d[e] != '@') ++e;
        if (e < n) j = e;
      }
    }
    if (j == std::string::npos || d.compare(j, 2, "@?") != 0) return 0;
    k = j + 2;
  }
  if (k < n && is_digit(d[k]) && d.compare(k + 1, 2, "??") == 0) return k + 3;
  size_t m = k;
  while (m < n && d[m] >= 'A' && d[m] <= 'P') ++m;
  if (m > k && m < n && d[m] == '@' && d.compare(m + 1, 2, "??") == 0) return m + 3;
  return 0;
}

}  // namespace verifier
