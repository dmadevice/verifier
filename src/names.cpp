#include "names.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <regex>
#include <stdexcept>

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

std::vector<std::pair<u64, std::string>> parse_map(const std::string& path) {
  std::vector<std::pair<u64, std::string>> syms;
  for_each_file_line(path, [&](std::string_view line) {
    std::string_view p[4];   // the first four whitespace-separated fields (str.split())
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
    syms.emplace_back(parse_hex(p[2]), std::string(p[1]));
  });
  return syms;
}

std::string norm_name(const std::string& in) {
  // re.sub(r"\s*__ptr64\b", "", s)
  std::string s;
  for (size_t i = 0; i < in.size();) {
    size_t j = i;
    while (j < in.size() && is_space(in[j])) ++j;
    if (in.compare(j, 7, "__ptr64") == 0 && (j + 7 == in.size() || !is_word(in[j + 7]))) { i = j + 7; continue; }
    s += in[i++];
  }
  // re.sub(r"\b(?:class|struct|enum|union) ", "", s)
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
  // re.sub(r"\s*([<>,*&])\s*", r"\1", s).strip()
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
  // re.sub(r"\b\w+::", "", s)
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
  // re.sub(r"\s+", " ", q).replace("( ", "(").replace(" )", ")")
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
    if (s.compare(i, 8, "operator") == 0 && (i + 8 == n || !is_word(s[i + 8]))) {   // (operator)(?!\w)(?:\(\))?[ops]*
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
  // OPERATOR_TAIL: r"operator(?:\(\)|[ops]+)$" (search: the leftmost start that matches)
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

std::optional<std::string> definition_name(const std::string& line0) {
  std::string ls = line0;
  size_t a = 0;
  while (a < ls.size() && is_space(ls[a])) ++a;
  if (ls.compare(a, 2, "//") == 0 || ls.compare(a, 1, "#") == 0) return std::nullopt;
  static const std::regex declspec(R"(__declspec\s*\([^)]*\))");
  std::string line = ls.find("__declspec") != std::string::npos ? std::regex_replace(ls, declspec, " ") : ls;
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
  // r"`([A-Za-z_]\w*)'::`\d+'::"
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

std::string static_owner(const std::string& und) {
  auto c = static_owner_c(und);
  return c ? *c : qualified(und);
}

static std::string fnptr_inner(const std::string& und) {
  if (und.find('*') == std::string::npos || und.find('(') == std::string::npos) return und;
  long i = param_start(und);
  if (i < 0) return und;
  static const std::regex head(R"(\((?:__\w+\s*)?\*)");
  static const std::regex fnptr(R"(\((?:__\w+\s*)?\*\s*(?:const\s+)?(?:__\w+\s+)?(.+)\)\s*\([^()]*\)[^()]*$)");
  std::string tail = und.substr(size_t(i));
  if (!std::regex_search(tail, head, std::regex_constants::match_continuous)) return und;
  std::smatch m;
  if (std::regex_search(tail, m, fnptr, std::regex_constants::match_continuous)) return m[1].str();
  return und;
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
    static const std::regex th(R"((?:`(.*)'::`\d+'::)?(`dynamic (?:initializer|atexit destructor) for '.*'')\(void\)$)");
    std::smatch m;
    if (std::regex_search(und, m, th)) {
      std::string g1 = m[1].matched ? m[1].str() : "";
      return norm_name((g1.empty() ? "" : static_owner(g1) + "::") + m[2].str());
    }
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

size_t local_static_match(const std::string& d) {
  // verify.LOCAL_STATIC: r"\?(?:\$S\d+|[^@?$][^@]*)@\?(?:\d|[A-P]+@)\?\?" (re.match)
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

// r'Undecoration of :- "(.*?)"\s*is :- "(.*?)"' (re.S), every match
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
// File: "verifier-names 1\n" key "\n", then per name: decorated \t has_und \t und \t qualified \t signature \t owner \n

NameCache::NameCache(std::string path, std::string key, std::string undname)
    : path_(std::move(path)), key_(std::move(key)), undname_(std::move(undname)) {
  if (path_.empty() || !file_exists(path_)) return;
  try {
    size_t k = 0;
    bool ok = true;
    for_each_file_line(path_, [&](std::string_view l) {
      size_t line = k++;
      if (!ok) return;
      if (line == 0) { ok = l == "verifier-names 1"; return; }
      if (line == 1) { ok = l == key_; return; }
      std::string_view f[6];
      size_t n = 0, p = 0;
      for (;;) {
        size_t q = l.find('\t', p);
        if (n == 6) { n = 7; break; }
        f[n++] = l.substr(p, q == std::string_view::npos ? std::string_view::npos : q - p);
        if (q == std::string_view::npos) break;
        p = q + 1;
      }
      if (n != 6) return;
      entries_[std::string(f[0])] = NameInfo{f[1] == "1", std::string(f[2]), std::string(f[3]), std::string(f[4]), std::string(f[5])};
    });
    if (!ok || k < 2) { entries_.clear(); return; }
    loaded_from_file_ = true;
    stored_ = entries_.size();
  } catch (...) {
    entries_.clear();
  }
}

void NameCache::load(const std::vector<std::string_view>& decorated) {
  std::vector<std::string> missing;
  for (auto& d : decorated) if (entries_.find(d) == entries_.end()) missing.emplace_back(d);
  std::sort(missing.begin(), missing.end());
  missing.erase(std::unique(missing.begin(), missing.end()), missing.end());
  auto und = undecorate(missing, undname_);
  for (auto& d : missing) {
    auto it = und.find(d);
    const std::string& u = it == und.end() ? d : it->second;
    entries_[d] = NameInfo{it != und.end(), it == und.end() ? "" : it->second, qualified(u), signature(u), static_owner(u)};
  }
  used_.clear();
  used_.reserve(decorated.size());
  for (auto& d : decorated) used_.push_back(entries_.find(d)->first);
}

void NameCache::save() {
  if (path_.empty()) return;
  std::vector<std::string_view> names(used_);
  std::sort(names.begin(), names.end());
  names.erase(std::unique(names.begin(), names.end()), names.end());
  if (loaded_from_file_ && names.size() == stored_) {
    bool same = true;
    for (auto& n : names) if (entries_.find(n) == entries_.end()) same = false;
    if (same) return;
  }
  std::string tmp = path_ + ".tmp";
  {
    std::ofstream f(tmp, std::ios::binary);
    if (!f) return;
    f << "verifier-names 1\n" << key_ << "\n";
    for (auto& n : names) {
      const NameInfo& ni = entries_.find(n)->second;
      f << n << '\t' << (ni.has_und ? "1" : "0") << '\t' << ni.und << '\t' << ni.qualified << '\t' << ni.signature << '\t'
        << ni.owner << '\n';
    }
  }
  std::error_code ec;
  std::filesystem::rename(tmp, path_, ec);   // readers see the old file or the new one
}

}  // namespace verifier
