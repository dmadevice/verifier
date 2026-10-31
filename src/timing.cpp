#include "timing.hpp"

#include <cstdio>
#include <cstdlib>

#ifdef _WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#else
#include <malloc.h>
#include <sys/resource.h>
#endif

namespace verifier {

Phases::Phases() : on_(std::getenv("VERIFIER_TIMING") != nullptr), t_(std::chrono::steady_clock::now()) {}

void Phases::mark(const char* what) {
  if (!on_) return;
  auto now = std::chrono::steady_clock::now();
  double ms = std::chrono::duration<double, std::milli>(now - t_).count();
  t_ = now;
  long rss = 0, heap = 0;
#ifdef _WIN32
  PROCESS_MEMORY_COUNTERS_EX pmc{};   // peak working set; private commit in use
  if (GetProcessMemoryInfo(GetCurrentProcess(), reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof pmc)) {
    rss = long(pmc.PeakWorkingSetSize >> 20);
    heap = long(pmc.PrivateUsage >> 20);
  }
#else
  rusage ru{};
  getrusage(RUSAGE_SELF, &ru);
  rss = ru.ru_maxrss / 1024;
#ifdef __GLIBC__
  heap = long(mallinfo2().uordblks >> 20);
#endif
#endif
  std::fprintf(stderr, "%-24s %8.1f ms  peak %ld MB  heap in use %ld MB\n", what, ms, rss, heap);
}

}  // namespace verifier
