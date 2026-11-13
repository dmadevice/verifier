// MSVC decorated names read in one pass into the keys symbols are paired by (names.hpp): the qualified name, the
// normalised parameter list and the function a local static belongs to. demangle.cpp says how they are spelled.
#pragma once
#include <memory>
#include <string>
#include <string_view>

namespace verifier {

struct NameKeys {
  std::string_view qualified, signature, owner;
};

class Demangler {
 public:
  Demangler();
  ~Demangler();
  Demangler(const Demangler&) = delete;
  Demangler& operator=(const Demangler&) = delete;
  // A map symbol's keys, as views of buffers the next call reuses. A name that is not a C++ decorated name (no leading
  // '?') or is an MD5-hashed one is its own qualified name and owner. false when the name cannot be read: the keys are
  // then the name itself as well.
  bool keys(std::string_view decorated, NameKeys& out);

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace verifier
