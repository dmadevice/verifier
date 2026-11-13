// The demangler: the keys and text of each kind of decorated name, and names it must fail on cleanly (cut short,
// damaged, nested too deeply) or read in full however long.
#include <random>
#include <string>
#include <vector>

#include "demangle.hpp"
#include "support.hpp"

namespace verifier::test {

namespace {

struct KeyCase {
  const char* decorated;
  const char *qualified, *signature, *owner;  // owner nullptr: the qualified name
};

const std::vector<KeyCase>& key_cases() {
  static const std::vector<KeyCase> cases = {
      // functions: members, special members, operators, templates
      {"?Get@Widget@@QEBAHXZ", "Widget::Get", "(void)", nullptr},
      {"??0Widget@@QEAA@AEBV0@@Z", "Widget::Widget", "(Widget const&)", nullptr},
      {"??1Widget@@UEAA@XZ", "Widget::~Widget", "(void)", nullptr},
      {"??_GWidget@@UEAAPEAXI@Z", "Widget::`scalar deleting destructor'", "(unsigned int)", nullptr},
      {"??MWidget@@QEBA_NAEBV0@@Z", "Widget::operator<", "(Widget const&)", nullptr},
      {"??RWidget@@QEAAHH@Z", "Widget::operator()", "(int)", nullptr},
      {"??3@YAXPEAX@Z", "operator delete", "(void*)", nullptr},
      {"??_U@YAPEAX_K@Z", "operator new[]", "(unsigned __int64)", nullptr},
      {"??BWidget@@QEBA_NXZ", "Widget::operator bool", "(void)", nullptr},
      {"?PushBack@?$Vector@H@N@@QEAAXAEBH@Z", "N::Vector<int>::PushBack", "(int const&)", nullptr},
      {"?PushBack@?$Vector@PEBUId@N@@@N@@QEAAXAEBQEBUId@2@_N@Z", "N::Vector<N::Id const*>::PushBack",
       "(Id const*const&,bool)", nullptr},
      {"?Size@?$Array@H$03@N@@QEBA_KXZ", "N::Array<int,4>::Size", "(void)", nullptr},
      {"??$Make@HM@@YAXHM@Z", "Make<int,float>", "(int,float)", nullptr},
      {"??$Get@H@Widget@@QEAAHXZ", "Widget::Get<int>", "(void)", nullptr},
      {"??$Apply@$$BY0E@H@@YAXXZ", "Apply<int [4]>", "(void)", nullptr},
      {"?h@@YA?AV?$Pair@HN@N@@XZ", "h", "(void)", nullptr},
      {"?k@@YAXV?$Tuple@$$V@N@@@Z", "k", "(Tuple<>)", nullptr},
      {"?Run@Widget@@SAXZZ", "Widget::Run", "(...)", nullptr},
      // parameters: back references, function and member pointers, arrays, references, nullptr_t
      {"?Swap@N@@YAXAEAVWidget@1@0@Z", "N::Swap", "(Widget&,Widget&)", nullptr},
      {"?select@@YAP6AHPEAUBox@@H@Z0@Z", "select", "(Box*)", nullptr},
      {"?f@@YAXP6AXH@Z@Z", "f", "(void (__cdecl*)(int))", nullptr},
      {"?Set@Widget@@QEAAXP81@EAAXXZ@Z", "Widget::Set", "(void (__cdecl *)(void))", nullptr},
      {"?g@@YAXPEAY03H@Z", "g", "(int (*)[4])", nullptr},
      {"?f@@YAX$$QEAVWidget@@@Z", "f", "(Widget&&)", nullptr},
      {"?f@@YAX$$T@Z", "f", "(nullptr_t)", nullptr},
      // an anonymous namespace: kept in the qualified name, dropped from the parameters
      {"?f@S@?A0x1234abcd@@QEAAXH@Z", "`anonymous namespace'::S::f", "(int)", nullptr},
      {"?f@@YAXPEAUS@?A0x1234abcd@@@Z", "f", "(S*)", nullptr},
      // thunks
      {"??_EWidget@@W7EAAPEAXI@Z", "Widget::`vector deleting destructor'`adjustor{8}'", "(unsigned int)", nullptr},
      {"?f@A@N@@$4PPPPPPPM@A@EAAXXZ", "N::A::f`vtordisp{4294967292,0}'", "(void)", nullptr},
      {"??_9Widget@@$BBA@AA", "Widget::`vcall'{16,{flat}}'", "", nullptr},
      // variables
      {"?g_count@N@@3HA", "N::g_count", "", nullptr},
      {"?s_max@Widget@@2HA", "Widget::s_max", "", nullptr},
      {"?g_ptr@@3PEAHEA", "g_ptr", "", nullptr},
      {"?g_grid@@3PAY03HA", "g_grid", "", nullptr},
      {"?v@@3PECHEC", "v", "", nullptr},
      {"?m@Widget@@0QEAHEA", "Widget::m", "", nullptr},
      {"?x@@3U?$Holder@$1?g_count@N@@3HA@@A", "x", "", nullptr},
      // local statics, their guards and destructors, and code the compiler names inside a function
      {"?count@?1??Get@Widget@@QEAAHXZ@4HA", "Widget::Get::count", "", "Widget::Get"},
      {"?$S1@?1??Get@Widget@@QEAAHXZ@4IA", "Widget::Get::$S1", "", "Widget::Get"},
      {"??__Fcount@?1??Get@Widget@@QEAAHXZ@YAXXZ", "Widget::Get::`dynamic atexit destructor for 'count''", "(void)",
       "Widget::Get"},
      {"?dtor$5@?0??Get@Widget@@QEAAHXZ@4HA", "Widget::Get::dtor$5", "", "Widget::Get"},
      {"??R<lambda_1>@?1??Run@Widget@@QEAAXXZ@QEBAXH@Z",
       "`public: void __cdecl Widget::Run(void)'::`2'::<lambda_1>::operator()", "(int)", nullptr},
      // dynamic initializers and atexit destructors
      {"??__Eg_table@N@@YAXXZ", "N::`dynamic initializer for 'g_table''", "(void)", nullptr},
      {"??__Fg_table@N@@YAXXZ", "N::`dynamic atexit destructor for 'g_table''", "(void)", nullptr},
      // tables and RTTI
      {"??_7Widget@@6B@", "Widget::`vftable'", "", nullptr},
      {"??_7Derived@@6BBase@@@", "Derived::`vftable'{for `Base'}", "", nullptr},
      {"??_8Derived@@7BBase@@@", "Derived::`vbtable'{for `Base'}", "", nullptr},
      {"??_R0?AVWidget@@@8", "Widget::`RTTI Type Descriptor'", "", nullptr},
      {"??_R1A@?0A@EA@Widget@@8", "Widget::`RTTI Base Class Descriptor at (0,-1,0,64)'", "", nullptr},
      {"??_R2Widget@@8", "Widget::`RTTI Base Class Array'", "", nullptr},
      {"??_R3Widget@@8", "Widget::`RTTI Class Hierarchy Descriptor'", "", nullptr},
      {"??_R4Widget@@6B@", "Widget::`RTTI Complete Object Locator'", "", nullptr},
      // names that are their own keys: strings, C names, hashed names
      {"??_C@_05ABCDEFGH@hello@", "`string'", "", nullptr},
      {"memcpy", "memcpy", "", nullptr},
      {"??@0123456789abcdef0123456789abcdef@", "??@0123456789abcdef0123456789abcdef@", "", nullptr},
  };
  return cases;
}

Findings keys_of_each_kind() {
  Findings bad;
  Demangler dm;
  for (auto& c : key_cases()) {
    NameKeys k;
    bool ok = dm.keys(c.decorated, k);
    std::string want_owner = c.owner ? c.owner : c.qualified;
    if (!ok || k.qualified != c.qualified || k.signature != c.signature || k.owner != want_owner)
      bad.push_back({"keys", std::string(c.decorated) + " -> " + std::string(k.qualified) + " | " +
                                 std::string(k.signature) + " | " + std::string(k.owner)});
  }
  return bad;
}

Findings whole_text() {
  std::vector<std::pair<const char*, const char*>> cases = {
      {"?Get@Widget@@QEBAHXZ", "public: int __cdecl Widget::Get(void)const"},
      {"??_EWidget@@W7EAAPEAXI@Z",
       "[thunk]:public: virtual void*__cdecl Widget::`vector deleting destructor'`adjustor{8}' (unsigned int)"},
      {"?select@@YAP6AHPEAUBox@@H@Z0@Z", "int (__cdecl*__cdecl select(Box*))(Box*,int)"},
      {"?count@?1??Get@Widget@@QEAAHXZ@4HA", "int `public: int __cdecl Widget::Get(void)'::`2'::count"},
      {"?$S1@?1??Get@Widget@@QEAAHXZ@4IA", "unsigned int `public: int __cdecl Widget::Get(void)'::`2'::$S1"},
      {"?g_grid@@3PAY03HA", "int (*g_grid)[4]"},
      {"?v@@3PECHEC", "int volatile*volatile v"},
      {"?PushBack@?$Vector@PEBUId@N@@@N@@QEAAXAEBQEBUId@2@_N@Z",
       "public: void __cdecl N::Vector<N::Id const*>::PushBack(N::Id const*const&,bool)"},
      {"??_7Derived@@6BBase@@@", "const Derived::`vftable'{for `Base'}"},
      {"??_R0?AVWidget@@@8", "Widget `RTTI Type Descriptor'"},
  };
  Findings bad;
  Demangler dm;
  for (auto& [d, want] : cases) {
    auto t = dm.text(d);
    if (t != want) bad.push_back({"text", std::string(d) + " -> " + t.value_or("(none)")});
  }
  if (dm.text("memcpy")) bad.push_back({"text", "a C name has a text"});
  return bad;
}

// a name that cannot be read: false, and the keys are the name itself
bool failed_cleanly(const std::string& d, bool ok, const NameKeys& k) {
  return ok || (k.qualified == d && k.owner == d && k.signature.empty());
}

// every name cut short, and each damaged in many ways: no crash, and a name that cannot be read fails cleanly
Findings damaged_names() {
  Findings bad;
  Demangler dm;
  std::mt19937 rng(12345);
  const std::string alphabet = "?@$0123456789ABCDEFGHPQRSTUVWXYZ_abc<>";
  size_t checked = 0;
  for (auto& c : key_cases()) {
    std::string d = c.decorated;
    for (size_t n = 0; n < d.size(); ++n) {
      std::string cut = d.substr(0, n);
      NameKeys k;
      bool ok = dm.keys(cut, k);
      if (!failed_cleanly(cut, ok, k)) bad.push_back({"cut", cut});
      (void)dm.text(cut);
      ++checked;
    }
    for (int i = 0; i < 400; ++i) {
      std::string m = d;
      for (int edits = 1 + int(rng() % 3); edits-- > 0;) {
        size_t at = m.empty() ? 0 : rng() % m.size();
        char ch = alphabet[rng() % alphabet.size()];
        switch (rng() % 3) {
          case 0:
            if (!m.empty()) m[at] = ch;
            break;
          case 1:
            m.insert(m.begin() + long(at), ch);
            break;
          default:
            if (!m.empty()) m.erase(at, 1);
        }
      }
      NameKeys k;
      bool ok = dm.keys(m, k);
      if (!failed_cleanly(m, ok, k)) bad.push_back({"mutated", m});
      (void)dm.text(m);
      ++checked;
    }
  }
  // the demangler is still right after all that
  NameKeys k;
  if (!dm.keys("?Get@Widget@@QEBAHXZ", k) || k.qualified != "Widget::Get") bad.push_back({"keys", "after damage"});
  if (checked < 1000) bad.push_back({"cut", "too few names checked"});
  return bad;
}

// names far longer than real ones, and nesting far deeper than recursion allows: read in full, or failed cleanly
Findings long_and_deep_names() {
  Findings bad;
  Demangler dm;
  const std::string x(200000, 'x');
  NameKeys k;
  // a long identifier in a template argument and in a dynamic initializer
  std::string tmpl = "?Get@?$Box@V" + x + "@@@N@@QEAAHXZ";
  if (!dm.keys(tmpl, k) || k.qualified != "N::Box<" + x + ">::Get" || k.signature != "(void)")
    bad.push_back({"long", "template argument"});
  std::string dyn = "??__Eg@?$Box@V" + x + "@@@N@@YAXXZ";
  if (!dm.keys(dyn, k) || k.qualified != "N::Box<" + x + ">::`dynamic initializer for 'g''")
    bad.push_back({"long", "dynamic initializer"});
  // many parameters (back references to the first)
  std::string params = "?f@@YAXPEAUBox@@";
  for (int i = 0; i < 20000; ++i) params += "0";
  params += "@Z";
  std::string want = "(Box*";
  for (int i = 0; i < 20000; ++i) want += ",Box*";
  want += ")";
  if (!dm.keys(params, k) || k.qualified != "f" || k.signature != want) bad.push_back({"long", "parameters"});
  // nesting: templates in templates, pointers to pointers, local scopes in local scopes
  std::string deep_tmpl = "?f@@YAXV";
  for (int i = 0; i < 100000; ++i) deep_tmpl += "?$A@V";
  deep_tmpl += "B@@";
  for (int i = 0; i < 100000; ++i) deep_tmpl += "@@";
  deep_tmpl += "@Z";
  std::string deep_ptr = "?f@@YAX";
  for (int i = 0; i < 100000; ++i) deep_ptr += "PEA";
  deep_ptr += "H@Z";
  std::string deep_local = "?x@";
  for (int i = 0; i < 100000; ++i) deep_local += "?1??g@";
  deep_local += "@YAXXZ@4HA";
  for (auto* d : {&deep_tmpl, &deep_ptr, &deep_local}) {
    bool ok = dm.keys(*d, k);
    if (!failed_cleanly(*d, ok, k)) bad.push_back({"deep", d->substr(0, 16)});
    (void)dm.text(*d);
  }
  // moderate nesting is read
  std::string ptrs = "?f@@YAX";
  for (int i = 0; i < 20; ++i) ptrs += "PEA";
  ptrs += "H@Z";
  if (!dm.keys(ptrs, k) || k.signature != "(int" + std::string(20, '*') + ")") bad.push_back({"deep", "20 pointers"});
  return bad;
}

}  // namespace

void add_demangle_cases(Cases& cases) {
  cases.insert(cases.end(), {
                                {"qualified names", nullptr, keys_of_each_kind},
                                {"demangled text", nullptr, whole_text},
                                {"damaged decorated names", nullptr, damaged_names},
                                {"long and deep decorated names", nullptr, long_and_deep_names},
                            });
}

}  // namespace verifier::test
