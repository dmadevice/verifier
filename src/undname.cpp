#include "undname.hpp"

#include <algorithm>
#include <stdexcept>

#include "util.hpp"

#ifdef _WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
extern char** environ;
#endif

namespace verifier {

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
      if (c == '\\') {
        ++bs;
        continue;
      }
      if (c == '"') {
        r.append(bs * 2 + 1, '\\');
        r += '"';
        bs = 0;
        continue;
      }
      r.append(bs, '\\');
      bs = 0;
      r += c;
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
    CloseHandle(rd);
    CloseHandle(wr);
    throw std::runtime_error("cannot run " + exe);
  }
  CloseHandle(wr);
  std::string out;
  char tmp[65536];
  DWORD got;
  while (ReadFile(rd, tmp, sizeof tmp, &got, nullptr) && got) out.append(tmp, got);
  CloseHandle(rd);
  WaitForSingleObject(pi.hProcess, INFINITE);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
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
  if (rc != 0) {
    close(fd[0]);
    throw std::runtime_error("cannot run " + exe);
  }
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
      if (out.compare(w, b.size(), b) == 0) {
        found = q;
        vs = w + b.size();
        break;
      }
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

std::unordered_map<std::string, std::string> undecorate(const std::vector<std::string>& names,
                                                        const std::string& undname) {
  std::vector<std::string> todo;
  for (auto& n : names)
    if (!n.empty() && n[0] == '?') todo.push_back(n);
  std::sort(todo.begin(), todo.end());
  todo.erase(std::unique(todo.begin(), todo.end()), todo.end());
  // batches of at most 200 names and 30000 characters (the Windows command line holds 32767)
  std::vector<std::vector<std::string>> batches;
  std::vector<std::string> cur;
  size_t size = 0;
  for (auto& n : todo) {
    if (!cur.empty() && (cur.size() == 200 || size + n.size() > 30000)) {
      batches.push_back(cur);
      cur.clear();
      size = 0;
    }
    cur.push_back(n);
    size += n.size() + 1;
  }
  if (!cur.empty()) batches.push_back(cur);
  std::unordered_map<std::string, std::string> res;
  for (auto& b : batches) parse_undname(run_capture(undname, b), res);
  return res;
}

}  // namespace verifier
