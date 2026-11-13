// Name handling on the source side: parameter lists, definitions, destructors, local static names.
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <random>
#include <set>
#include <string>
#include <vector>

#include "support.hpp"

namespace verifier::test {

namespace {

// annotations' parameter lists, spelled as written or as undname prints them, normalised alike
Findings param_lists() {
  Findings bad;
  if (norm_params("(char const *)") != norm_params("(char const*)") || norm_params("()") != "(void)")
    bad.push_back({"signature", "norm_params spelling"});
  if (norm_params("(class N::Widget const & __ptr64,int)") != "(Widget const&,int)")
    bad.push_back({"signature", "norm_params scopes"});
  if (norm_params("(struct `anonymous namespace'::S *)") != norm_params("(S*)"))
    bad.push_back({"signature", "norm_params anonymous namespace"});
  return bad;
}

Findings definition_names() {
  std::vector<std::pair<std::string, std::optional<std::string>>> cases = {
      {"String& String::operator=(const Char* c)", "String::operator="},
      {"Value& Value::operator[](Int32 index)", "Value::operator[]"},
      {"bool S::operator<(const S& o) const", "S::operator<"},
      {"__declspec(noinline) void N::S::Clear()", "N::S::Clear"},
      {"Gfx::Color N::Model::GetColor(int i) const", "N::Model::GetColor"},
      {"extern \"C\" void* __fastcall sub_180001000(void*, unsigned int)", "sub_180001000"},
      {"const Vector<Value*>* Foo::Bar()", "Foo::Bar"},
      {"    virtual ~Exc() throw() {}", "~Exc"},
      {"// FUNCTION: EXAMPLE 0x180001000 (int)", std::nullopt},
      {"{", std::nullopt},
  };
  Findings bad;
  for (auto& [line, want] : cases)
    if (definition_name(line) != want) bad.push_back({"name", line + " -> " + definition_name(line).value_or("None")});
  return bad;
}

// declarations far longer than the recursion of a backtracking regex engine allows (the demangler's own long-name
// cases are in demangle_test.cpp)
Findings long_names() {
  const std::string x(200000, 'x');
  Findings bad;
  if (global_decl_name("static int " + x + "[4][2] = {};") != x) bad.push_back({"global", "declaration"});
  if (global_decl_name(x + " " + x)) bad.push_back({"global", "no declaration"});
  if (class_decl_name("class __declspec(novtable) N::" + x + " : public B {") != "N::" + x)
    bad.push_back({"class", "declaration"});
  if (definition_name("__declspec(noinline) void N::" + x + "(int)") != "N::" + x)
    bad.push_back({"name", "definition"});
  return bad;
}

Findings destructor_pairing() {
  std::string dd = "N::X::`scalar deleting destructor'";
  auto both = [](const std::string&) { return true; };
  std::function<bool(const std::string&)> only_dd = [&](const std::string& n) { return n == dd; };
  std::function<bool(const std::string&)> no_dd = [&](const std::string& n) { return n != dd; };
  struct C {
    bool in_slot;
    std::function<bool(const std::string&)> has;
    std::string want;
  };
  std::vector<C> cases = {{true, both, dd}, {false, both, "N::X::~X"}, {false, only_dd, dd}, {true, no_dd, "N::X::~X"}};
  Findings bad;
  for (auto& c : cases) {
    auto got = pick_destructor("N::X::~X", c.in_slot, c.has);
    if (got != c.want) bad.push_back({"name", got});
  }
  return bad;
}

Findings local_static_names() {
  std::vector<std::pair<std::string, bool>> cases = {
      {"?$S3@?1??GetSharedMutex@@YAPEAVmutex@std@@XZ@4IA", true},
      {"?unpacked@?1??unpack_language@@YAPEADG@Z@4PADA", true},
      {"?table@?BA@??read_record@@YAHPEAUrecord@@PEAX@Z@4QBU<unnamed-type-table>"
       "@?BA@??1@YAH01@Z@B",
       true},
      {"??_B?1??Get@Widget@@SAAEAV1@XZ@51", true},
      {"??_B?BA@??Get@Widget@@SAAEAV1@XZ@51", true},
      {"??_7Widget@@6B@", false},
      {"??_B?1?Get@Widget@@SAAEAV1@XZ@51", false},
      {"??_Bx?1??Get@Widget@@SAAEAV1@XZ@51", false},
      {"?g_foo@@3HA", false},
      {"?x@Cls@@2HA", false},
      {"?x@?A0x12345678@ns@@3HA", false},
  };
  Findings bad;
  for (auto& [n, want] : cases)
    if ((local_static_match(n) != 0) != want) bad.push_back({"local static", n});
  return bad;
}

}  // namespace

void add_names_cases(Cases& cases) {
  cases.insert(cases.end(), {
                                {"parameter lists", nullptr, param_lists},
                                {"definition names", nullptr, definition_names},
                                {"long names", nullptr, long_names},
                                {"destructor pairing", nullptr, destructor_pairing},
                                {"local static names", nullptr, local_static_names},
                            });
}

}  // namespace verifier::test
