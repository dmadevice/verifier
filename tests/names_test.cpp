// Name handling: qualified names, signatures, definitions, destructors, local static names.
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

Findings qualified_names() {
  std::vector<std::pair<std::string, std::string>> cases = {
      {"public: virtual void * __cdecl A::B::`scalar deleting destructor'(unsigned int)",
       "A::B::`scalar deleting destructor'"},
      {"[thunk]:public: virtual void * __cdecl A::B::`scalar deleting destructor'`adjustor{8}' (unsigned int)",
       "A::B::`scalar deleting destructor'`adjustor{8}'"},
      {"[thunk]:public: virtual void * __cdecl A::C::`vector deleting destructor'`adjustor{8}' (unsigned int)",
       "A::C::`vector deleting destructor'`adjustor{8}'"},
      {"public: int __cdecl A::B::Get(void)const ", "A::B::Get"},
      {"public: void __cdecl N::Vector<struct N::Id const * __ptr64>::PushBack(struct N::Id const * __ptr64 const & "
       "__ptr64,bool) __ptr64",
       "N::Vector<N::Id const*>::PushBack"},
      {"public: virtual void * __ptr64 __cdecl N::Vector<struct N::Id const * __ptr64>::`scalar deleting "
       "destructor'(unsigned int) __ptr64",
       "N::Vector<N::Id const*>::`scalar deleting destructor'"},
      {"public: bool __cdecl N::S::operator<(class N::S const & __ptr64)const __ptr64", "N::S::operator<"},
      {"public: bool __cdecl N::S::operator>(class N::S const & __ptr64)const __ptr64", "N::S::operator>"},
      {"public: int __cdecl N::F::operator()(int) __ptr64", "N::F::operator()"},
      {"void __cdecl operator delete(void * __ptr64)", "operator delete"},
      {"void * __ptr64 __cdecl operator new[](unsigned __int64)", "operator new[]"},
      {"public: __cdecl N::S::operator bool(void)const __ptr64", "N::S::operator bool"},
      {"void __cdecl `dynamic atexit destructor for 'g_x''(void)", "`dynamic atexit destructor for 'g_x''"},
      {"void __cdecl `dynamic initializer for 'N::g_x''(void)", "`dynamic initializer for 'N::g_x''"},
      {"void __cdecl `struct S const * __ptr64 __cdecl N::f(int)'::`2'::`dynamic atexit destructor for 's_x''(void)",
       "N::f::`dynamic atexit destructor for 's_x''"},
      {"[thunk]:public: virtual void * __ptr64 __cdecl N::A::`vector deleting destructor'`vtordisp{4294967292,0}' "
       "(unsigned int) __ptr64",
       "N::A::`vector deleting destructor'`vtordisp{4294967292,0}'"},
      {"public: void __cdecl N::E<class N::I * __ptr64>::`vbase destructor'(void) __ptr64",
       "N::E<N::I*>::`vbase destructor'"},
      {"public: void __cdecl `anonymous namespace'::S::f(int) __ptr64", "`anonymous namespace'::S::f"},
      {"int (__cdecl*__cdecl select_printer(struct box * __ptr64))(struct _iobuf * __ptr64,int)", "select_printer"},
      // returning a pointer to member function: `(__cdecl <class>::*` before the name
      {"public: void (__cdecl Foo::*__cdecl Foo::Get(void) __ptr64)(void) __ptr64", "Foo::Get"},
      {"public: static int (__cdecl N::T<class N::A,int>::*__cdecl N::T<class N::A,int>::Pick(int))(int)const "
       "__ptr64",
       "N::T<N::A,int>::Pick"},
      {"public: void __cdecl Foo::Set(void (__cdecl Foo::*)(void) __ptr64) __ptr64", "Foo::Set"},
  };
  Findings bad;
  for (auto& [u, want] : cases)
    if (qualified(u) != want) bad.push_back({"name", u + " -> " + qualified(u)});
  std::vector<std::pair<std::string, std::string>> owners = {
      {"int `int __cdecl N::f(void)'::`2'::x", "N::f"},
      {"unsigned __int64 `__local_stdio_printf_options'::`2'::_OptionsStorage", "__local_stdio_printf_options"},
  };
  for (auto& [u, want] : owners)
    if (static_owner(u) != want) bad.push_back({"static owner", u + " -> " + static_owner(u)});
  std::vector<std::pair<std::string, std::string>> sigs = {
      {"void __cdecl operator delete(void * __ptr64)", "(void*)"},
      {"void __cdecl operator delete(void * __ptr64,unsigned __int64)", "(void*,unsigned __int64)"},
      {"public: __cdecl N::S::S(class N::S const & __ptr64) __ptr64", "(S const&)"},
      {"public: int __cdecl A::B::Get(void)const ", "(void)"},
      {"public: bool __cdecl N::S::operator<(class N::S const & __ptr64)const __ptr64", "(S const&)"},
      {"int (__cdecl*__cdecl select_printer(struct box * __ptr64))(struct _iobuf * __ptr64,int)", "(box*)"},
      {"void __cdecl f(void (__cdecl*)(int))", "(void (__cdecl*)(int))"},
      {"public: void (__cdecl Foo::*__cdecl Foo::Get(int) __ptr64)(void) __ptr64", "(int)"},
  };
  for (auto& [u, want] : sigs)
    if (signature(u) != want) bad.push_back({"signature", u + " -> " + signature(u)});
  if (norm_params("(char const *)") != norm_params("(char const*)") || norm_params("()") != "(void)")
    bad.push_back({"signature", "norm_params spelling"});
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

// names far longer than the recursion of a backtracking regex engine allows (real builds have undecorated
// names tens of thousands of characters long)
Findings long_names() {
  const std::string x(200000, 'x');
  Findings bad;
  std::string dyn = "void __cdecl `dynamic initializer for 'N::g<" + x + ">''(void)";
  if (qualified(dyn) != "`dynamic initializer for 'N::g<" + x + ">''") bad.push_back({"name", "dynamic initializer"});
  std::string local =
      "void __cdecl `int __cdecl N::f<" + x + ">(void)'::`2'::`dynamic atexit destructor for 's''(void)";
  if (qualified(local) != "N::f<" + x + ">::`dynamic atexit destructor for 's''")
    bad.push_back({"name", "local atexit destructor"});
  std::string params;
  for (int i = 0; i < 20000; ++i) params += i ? ",struct box * __ptr64" : "struct box * __ptr64";
  std::string fp = "int (__cdecl*__cdecl select_printer(" + params + "))(struct _iobuf * __ptr64,int)";
  if (qualified(fp) != "select_printer") bad.push_back({"name", "function returning a function pointer"});
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
      {"qualified names", nullptr, qualified_names},
      {"definition names", nullptr, definition_names},
      {"long names", nullptr, long_names},
      {"destructor pairing", nullptr, destructor_pairing},
      {"local static names", nullptr, local_static_names},
  });
}

}  // namespace verifier::test
