// VERIFIER_TIMING=1: each phase's wall time and the peak memory so far, on stderr.
#pragma once
#include <chrono>

namespace verifier {

class Phases {
 public:
  Phases();
  void mark(const char* what);  // the time since the last mark (or the start), under `what`

 private:
  bool on_;
  std::chrono::steady_clock::time_point t_;
};

}  // namespace verifier
