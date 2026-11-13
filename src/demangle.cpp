#include "demangle.hpp"

#include <charconv>
#include <optional>
#include <vector>

#include "util.hpp"

// The grammar is MSVC's (as LLVM's MicrosoftDemangle reads it): a symbol is a qualified name and an encoding (a
// function's class and type, or a variable's storage class and type), names and types refer back to earlier ones,
// and a template's arguments have back references of their own. A name is parsed into a small tree held in reusable
// arrays, then its keys are printed from the tree.
//
// The spelling is undname's, normalised (names.hpp: norm_name, norm_params), except where that says less or more
// than the name:
// - a function's local scope is the function's qualified name (`f::x`, `f::Local::g`), not its whole text and a
//   scope number;
// - a class template's constructor and destructor are named by the class's name alone (`V<int>::~V`);
// - __cdecl is not written in function types; a template argument that is an address is `&name`, without a type;
// - a pointer keeps its own const and volatile where undname drops them (returned, or an array's element), and a
//   variable that is a pointer has the qualifiers of its storage class, not its pointee's.
//
// And the tree is read as the compiler meant it where undname does not:
// - a name the compiler builds by joining a function's own decorated name into another (an EH funclet's label such as
//   `dtor$4`, a dynamic initializer or atexit destructor of a local static) has that function's back references
//   counted from its start, not shared with the enclosing name;
// - `?$S1@` at a symbol's start is a guard variable's name, not a template;
// - a back reference to an anonymous namespace is that namespace, not its hash;
// - a vcall thunk's name ends after its offset and `{flat}`.

namespace verifier {

namespace {

enum class NK : u8 {
  None,
  List,  // a list cell: x the item, next the next cell
  // identifiers (one component of a qualified name)
  Simple,      // s
  Anon,        // `anonymous namespace'
  Template,    // x: the name's identifier; y: argument cells
  Local,       // `<x: the function>'::`v'
  Text,        // s, printed as it is (an operator, a special name)
  Structor,    // a: destructor; x: the class's identifier (the component before it)
  Conversion,  // x: the target type (the function's return type)
  Dynamic,     // a: atexit destructor; x: the variable's qualified name
  Guard,       // a: thread guard; v: the scope index (0: none)
  BaseDesc,    // y: cells of the four numbers (Int)
  Vcall,       // v: the offset
  LiteralOp,   // s: the suffix
  // a qualified name: x the component cells, outermost first; v the count
  Qualified,
  // types (a: cv qualifiers)
  Prim,      // s
  Nullptr,   //
  Tag,       // x: qualified name
  Pointer,   // x: pointee; y: a member pointer's class (qualified name); b: affinity
  Function,  // x: return type (0: none); y: parameter cells; b: ref qualifier; c: flags; s: calling convention
  Array,     // x: dimension cells (Int); y: element type
  // template arguments
  Int,        // v; a: negative
  SymbolRef,  // x: symbol (0: none); y: offset cells (Int); b: 1 when printed as an address ("&")
  // symbols
  FuncSym,   // x: qualified name; y: Function; z: thunk offset cells (Int); v: function class
  VarSym,    // x: qualified name; y: type; a: storage class
  Table,     // x: qualified name; y: {for} cells (qualified names); a: cv qualifiers
  TypeDesc,  // x: type
  Untyped,   // x: qualified name (RTTI base class arrays, hierarchy and base class descriptors, guards, vcalls)
  StrLit,    //
  Md5,       // s
};

struct Node {
  NK kind = NK::None;
  u8 a = 0, b = 0, c = 0;
  u32 x = 0, y = 0, z = 0, next = 0;
  u64 v = 0;
  std::string_view s;
};

constexpr u8 Q_CONST = 1, Q_VOLATILE = 2, Q_RESTRICT = 4, Q_UNALIGNED = 8;
constexpr u8 AFF_POINTER = 0, AFF_REF = 1, AFF_RREF = 2;
constexpr u8 F_VARIADIC = 1, F_NOEXCEPT = 2, F_NO_PARAMS = 4;
// function classes
constexpr u32 FC_PRIVATE = 1, FC_PROTECTED = 2, FC_PUBLIC = 4, FC_GLOBAL = 8, FC_STATIC = 16, FC_VIRTUAL = 32,
              FC_EXTERN_C = 128, FC_NO_PARAMS = 256, FC_VTORDISP = 512, FC_VTORDISP_EX = 1024, FC_ADJUSTOR = 2048;

constexpr std::string_view ANON = "`anonymous namespace'";

constexpr int MAX_DEPTH = 192;           // parse and print recursion
constexpr size_t MAX_NODES = 1u << 20;   // per name
constexpr size_t MAX_OUTPUT = 1u << 20;  // bytes of one printed key

// norm_name keeps no whitespace next to these
bool tight(char c) { return c == '<' || c == '>' || c == ',' || c == '*' || c == '&'; }

// The text a code character stands for, in a table of them; nullptr when the table has none for it
struct Coded {
  char code;
  const char* text;
};
template <size_t N>
const char* coded(const Coded (&table)[N], char c) {
  for (const Coded& e : table)
    if (e.code == c) return e.text;
  return nullptr;
}

constexpr Coded BASIC_OPERATORS[] = {
    // ?<code>
    {'2', "operator new"}, {'3', "operator delete"}, {'4', "operator="},  {'5', "operator>>"}, {'6', "operator<<"},
    {'7', "operator!"},    {'8', "operator=="},      {'9', "operator!="}, {'A', "operator[]"}, {'C', "operator->"},
    {'D', "operator*"},    {'E', "operator++"},      {'F', "operator--"}, {'G', "operator-"},  {'H', "operator+"},
    {'I', "operator&"},    {'J', "operator->*"},     {'K', "operator/"},  {'L', "operator%"},  {'M', "operator<"},
    {'N', "operator<="},   {'O', "operator>"},       {'P', "operator>="}, {'Q', "operator,"},  {'R', "operator()"},
    {'S', "operator~"},    {'T', "operator^"},       {'U', "operator|"},  {'V', "operator&&"}, {'W', "operator||"},
    {'X', "operator*="},   {'Y', "operator+="},      {'Z', "operator-="},
};

constexpr Coded UNDER_OPERATORS[] = {
    // ?_<code>
    {'0', "operator/="},
    {'1', "operator%="},
    {'2', "operator>>="},
    {'3', "operator<<="},
    {'4', "operator&="},
    {'5', "operator|="},
    {'6', "operator^="},
    {'D', "`vbase destructor'"},
    {'E', "`vector deleting destructor'"},
    {'F', "`default constructor closure'"},
    {'G', "`scalar deleting destructor'"},
    {'H', "`vector constructor iterator'"},
    {'I', "`vector destructor iterator'"},
    {'J', "`vector vbase constructor iterator'"},
    {'K', "`virtual displacement map'"},
    {'L', "`eh vector constructor iterator'"},
    {'M', "`eh vector destructor iterator'"},
    {'N', "`eh vector vbase constructor iterator'"},
    {'O', "`copy constructor closure'"},
    {'T', "`local vftable constructor closure'"},
    {'U', "operator new[]"},
    {'V', "operator delete[]"},
    {'X', "`placement delete closure'"},
    {'Y', "`placement delete[] closure'"},
};

constexpr Coded DOUBLE_UNDER_OPERATORS[] = {
    // ?__<code>
    {'A', "`managed vector constructor iterator'"},
    {'B', "`managed vector destructor iterator'"},
    {'C', "`eh vector copy constructor iterator'"},
    {'D', "`eh vector vbase copy constructor iterator'"},
    {'G', "`vector copy constructor iterator'"},
    {'H', "`vector vbase copy constructor iterator'"},
    {'I', "`managed vector copy constructor iterator'"},
    {'L', "operator co_await"},
    {'M', "operator<=>"},
};

constexpr Coded PRIMITIVES[] = {
    {'X', "void"},           {'D', "char"},   {'C', "signed char"},  {'E', "unsigned char"}, {'F', "short"},
    {'G', "unsigned short"}, {'H', "int"},    {'I', "unsigned int"}, {'J', "long"},          {'K', "unsigned long"},
    {'M', "float"},          {'N', "double"}, {'O', "long double"},
};

constexpr Coded EXTENDED_PRIMITIVES[] = {
    // _<code>
    {'D', "__int8"},   {'E', "unsigned __int8"},   {'F', "__int16"}, {'G', "unsigned __int16"},
    {'H', "__int32"},  {'I', "unsigned __int32"},  {'J', "__int64"}, {'K', "unsigned __int64"},
    {'L', "__int128"}, {'M', "unsigned __int128"}, {'N', "bool"},    {'Q', "char8_t"},
    {'S', "char16_t"}, {'U', "char32_t"},          {'W', "wchar_t"},
};

// A to Q: two codes each; K and L have none
const char* calling_convention(char c) {
  static constexpr const char* names[] = {"__cdecl", "__pascal",  "__thiscall", "__stdcall",   "__fastcall",
                                          nullptr,   "__clrcall", "__eabi",     "__vectorcall"};
  return c >= 'A' && c <= 'Q' ? names[(c - 'A') / 2] : nullptr;
}

// a funclet's label (`dtor$4`, `catch$0`): letters, '$', digits
bool generated_label(std::string_view s) {
  size_t i = 0;
  while (i < s.size() && ((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= 'A' && s[i] <= 'Z') || s[i] == '_')) ++i;
  if (i == 0 || i == s.size() || s[i] != '$') return false;
  size_t d = ++i;
  while (i < s.size() && is_digit(s[i])) ++i;
  return i > d && i == s.size();
}

}  // namespace

struct Demangler::Impl {
  // --- input and tree -------------------------------------------------------------------------------------------
  std::string_view in;
  size_t pos = 0;
  bool err = false;
  int depth = 0;
  std::vector<Node> nodes;
  std::vector<u32> stack;  // scratch for scope chains
  struct Backrefs {
    u32 names[10];
    std::string_view keys[10];  // what decides whether a name is already there
    u32 nnames = 0;
    u32 params[10];
    u32 nparams = 0;
  } br;

  // --- output ---------------------------------------------------------------------------------------------------
  std::string* out = nullptr;
  bool sig = false;                              // dropping `word::` as norm_params does
  std::vector<std::pair<size_t, size_t>> drops;  // [from, to) of *out, in order
  std::string qual, sigbuf, owner;

  struct Depth {
    Impl& p;
    explicit Depth(Impl& p) : p(p) {
      if (++p.depth > MAX_DEPTH) p.err = true;
    }
    ~Depth() { --p.depth; }
  };

  void reset(std::string_view d) {
    in = d;
    pos = 0;
    err = false;
    depth = 0;
    nodes.clear();
    nodes.emplace_back();  // node 0: none
    stack.clear();
    br = Backrefs{};
  }

  char peek(size_t k = 0) const { return pos + k < in.size() ? in[pos + k] : '\0'; }
  bool at_end() const { return pos >= in.size(); }
  bool starts(std::string_view t) const { return in.size() - pos >= t.size() && in.compare(pos, t.size(), t) == 0; }
  bool eat(char c) {
    if (pos < in.size() && in[pos] == c) {
      ++pos;
      return true;
    }
    return false;
  }
  bool eat(std::string_view t) {
    if (!starts(t)) return false;
    pos += t.size();
    return true;
  }
  char take() { return pos < in.size() ? in[pos++] : (err = true, '\0'); }
  u32 fail() {
    err = true;
    return 0;
  }
  u32 add(NK k) {
    if (nodes.size() >= MAX_NODES) return fail();
    nodes.emplace_back().kind = k;
    return u32(nodes.size() - 1);
  }
  Node& n(u32 i) { return nodes[i]; }

  // a list: append item to (head, tail)
  void append(u32& head, u32& tail, u32 item) {
    u32 c = add(NK::List);
    if (!c) return;
    n(c).x = item;
    if (tail)
      n(tail).next = c;
    else
      head = c;
    tail = c;
  }

  // --- numbers --------------------------------------------------------------------------------------------------

  // [?] a digit (value + 1) or hex digits A-P ending in '@'
  u64 number(bool& neg) {
    neg = eat('?');
    char c = peek();
    if (is_digit(c)) {
      ++pos;
      return u64(c - '0') + 1;
    }
    u64 r = 0;
    for (int k = 0;; ++k) {
      c = peek();
      if (c == '@') {
        ++pos;
        return r;
      }
      if (c < 'A' || c > 'P' || k == 16) {
        err = true;
        return 0;
      }
      r = (r << 4) | u64(c - 'A');
      ++pos;
    }
  }
  u64 unsigned_number() {
    bool neg;
    u64 v = number(neg);
    if (neg) err = true;
    return v;
  }
  u32 int_node() {
    bool neg;
    u64 v = number(neg);
    if (err) return 0;
    u32 i = add(NK::Int);
    if (!i) return 0;
    n(i).v = v;
    n(i).a = neg;
    return i;
  }

  // --- names ----------------------------------------------------------------------------------------------------

  void memorize(std::string_view key, u32 node) {
    if (br.nnames >= 10) return;
    for (u32 i = 0; i < br.nnames; ++i)
      if (br.keys[i] == key) return;
    br.keys[br.nnames] = key;
    br.names[br.nnames++] = node;
  }

  std::string_view simple_text() {
    size_t e = in.find('@', pos);
    if (e == std::string_view::npos || e == pos) {
      err = true;
      return {};
    }
    std::string_view s = in.substr(pos, e - pos);
    pos = e + 1;
    return s;
  }

  u32 simple(bool memo) {
    std::string_view s = simple_text();
    if (err) return 0;
    u32 i = add(NK::Simple);
    if (!i) return 0;
    n(i).s = s;
    if (memo) memorize(s, i);
    return i;
  }

  u32 backref_name() {
    u32 k = u32(take() - '0');
    if (k >= br.nnames) return fail();
    return br.names[k];
  }

  // ?$<name><arguments>@: the arguments have back references of their own
  u32 template_name(bool memo) {
    Depth d(*this);
    if (err) return 0;
    size_t start = pos;
    pos += 2;
    Backrefs outer = br;
    br = Backrefs{};
    u32 name = unqualified_symbol_name(true, false);
    u32 args = err ? 0 : template_args();
    br = outer;
    if (err) return 0;
    u32 t = add(NK::Template);
    if (!t) return 0;
    n(t).x = name;
    n(t).y = args;
    if (memo) memorize(in.substr(start, pos - start), t);
    return t;
  }

  u32 unqualified_symbol_name(bool memo_simple, bool memo_template) {
    char c = peek();
    if (is_digit(c)) return backref_name();
    if (starts("?$")) return template_name(memo_template);
    if (c == '?') return operator_name();
    return simple(memo_simple);
  }

  u32 text_node(const char* t) {
    if (!t) return fail();
    u32 i = add(NK::Text);
    if (i) n(i).s = t;
    return i;
  }

  // ?<code>: an operator, a constructor or destructor, a special function
  u32 operator_name() {
    ++pos;  // '?'
    if (eat("__")) {
      char c = take();
      if (c == 'K') {
        std::string_view s = simple_text();
        if (err) return 0;
        u32 i = add(NK::LiteralOp);
        if (i) n(i).s = s;
        return i;
      }
      return text_node(coded(DOUBLE_UNDER_OPERATORS, c));
    }
    if (eat('_')) return text_node(coded(UNDER_OPERATORS, take()));
    char c = take();
    if (c == '0' || c == '1') {
      u32 i = add(NK::Structor);
      if (i) n(i).a = c == '1';
      return i;
    }
    if (c == 'B') return add(NK::Conversion);
    return text_node(coded(BASIC_OPERATORS, c));
  }

  // ?<number>? : a function's local scope
  bool local_scope_ahead() const {
    if (peek() != '?') return false;
    size_t i = pos + 1, e = i;
    while (e < in.size() && e - i < 20 && in[e] != '?') ++e;
    if (e >= in.size() || in[e] != '?' || e == i) return false;
    std::string_view c = in.substr(i, e - i);
    if (c.size() == 1) return c[0] == '@' || is_digit(c[0]);
    if (c.back() != '@' || c[0] < 'B' || c[0] > 'P') return false;
    for (size_t k = 1; k + 1 < c.size(); ++k)
      if (c[k] < 'A' || c[k] > 'P') return false;
    return true;
  }

  u32 local_scope(bool fresh) {
    ++pos;  // '?'
    u64 v = unsigned_number();
    if (err || !eat('?')) return fail();
    u32 sym;
    if (fresh) {
      Backrefs outer = br;
      br = Backrefs{};
      sym = symbol();
      br = outer;
    } else {
      sym = symbol();
    }
    if (err) return 0;
    u32 i = add(NK::Local);
    if (!i) return 0;
    n(i).x = sym;
    n(i).v = v;
    return i;
  }

  u32 anonymous_namespace() {
    size_t start = pos;
    size_t e = in.find('@', pos + 2);
    if (e == std::string_view::npos) return fail();
    pos = e + 1;
    u32 i = add(NK::Anon);
    if (i) memorize(in.substr(start, e - start), i);
    return i;
  }

  u32 scope_piece(bool& fresh) {
    char c = peek();
    if (is_digit(c)) return backref_name();
    if (starts("?$")) return template_name(true);
    if (starts("?A")) return anonymous_namespace();
    if (local_scope_ahead()) {
      bool f = fresh;
      fresh = false;
      return local_scope(f);
    }
    return simple(true);
  }

  // the scopes after the innermost component, to the '@' that ends them: a qualified name. fresh: the first local
  // scope's function has back references of its own
  u32 scope_chain(u32 leaf, bool fresh = false) {
    Depth d(*this);
    if (err) return 0;
    size_t base = stack.size();
    stack.push_back(leaf);
    while (!eat('@')) {
      if (at_end()) {
        err = true;
        break;
      }
      u32 piece = scope_piece(fresh);
      if (err) break;
      stack.push_back(piece);
    }
    if (err) {
      stack.resize(base);
      return 0;
    }
    u32 head = 0;
    for (size_t k = base; k < stack.size(); ++k) {  // innermost first: each cell goes before the last
      u32 c = add(NK::List);
      if (!c) break;
      n(c).x = stack[k];
      n(c).next = head;
      head = c;
    }
    u64 count = stack.size() - base;
    stack.resize(base);
    u32 q = err ? 0 : add(NK::Qualified);
    if (!q) return 0;
    n(q).x = head;
    n(q).v = count;
    return q;
  }

  // the innermost component of a qualified name, and the one before it (0: none)
  u32 component(u32 qn, u64 from_end) const {
    const Node& q = nodes[qn];
    if (from_end >= q.v) return 0;
    u32 c = q.x;
    for (u64 k = 0; k + 1 + from_end < q.v; ++k) c = nodes[c].next;
    return nodes[c].x;
  }

  // an identifier of this kind, or the name of a template that is one (a templated constructor or conversion
  // operator); 0 when `id` is neither
  u32 named(u32 id, NK kind) const {
    if (nodes[id].kind == kind) return id;
    if (nodes[id].kind == NK::Template && nodes[nodes[id].x].kind == kind) return nodes[id].x;
    return 0;
  }
  u32 structor_of(u32 id) const { return named(id, NK::Structor); }  // its class is the component before it
  u32 conversion_of(u32 id) const { return named(id, NK::Conversion); }

  u32 symbol_name(bool fresh_local) {
    u32 leaf = unqualified_symbol_name(true, false);
    if (err) return 0;
    bool fresh = fresh_local || (n(leaf).kind == NK::Simple && generated_label(n(leaf).s));
    u32 qn = scope_chain(leaf, fresh);
    if (err) return 0;
    if (u32 st = structor_of(leaf)) {
      if (n(qn).v < 2) return fail();
      n(st).x = component(qn, 1);
    }
    return qn;
  }

  u32 type_name() {
    u32 leaf;
    if (is_digit(peek()))
      leaf = backref_name();
    else if (starts("?$"))
      leaf = template_name(true);
    else
      leaf = simple(true);
    if (err) return 0;
    return scope_chain(leaf);
  }

  // --- types ----------------------------------------------------------------------------------------------------

  // A B C D (Q R S T: of a member)
  u8 qualifiers(bool* member = nullptr) {
    char c = take();
    bool m = c >= 'Q';
    unsigned k = unsigned(c - (m ? 'Q' : 'A'));  // 0 to 3: none, const, volatile, both
    if (c < 'A' || k > 3) {
      err = true;
      k = 0;
    }
    if (member) *member = m;
    return u8((k & 1 ? Q_CONST : 0) | (k & 2 ? Q_VOLATILE : 0));
  }

  u8 ext_qualifiers() {
    u8 q = 0;
    eat('E');  // __ptr64: not printed (norm_name drops it)
    if (eat('I')) q |= Q_RESTRICT;
    if (eat('F')) q |= Q_UNALIGNED;
    return q;
  }

  bool pointer_ahead() const {
    if (starts("$$Q") || starts("$$R")) return true;
    char c = peek();
    return c == 'A' || c == 'B' || c == 'P' || c == 'Q' || c == 'R' || c == 'S';
  }

  // P Q R S followed by a member's qualifiers (or 8: a member function)
  bool member_pointer_ahead() {
    char c = peek();
    if (c != 'P' && c != 'Q' && c != 'R' && c != 'S') return false;
    size_t i = pos + 1;
    if (i < in.size() && is_digit(in[i])) {
      if (in[i] != '6' && in[i] != '8') err = true;
      return in[i] == '8';
    }
    if (i < in.size() && in[i] == 'E') ++i;
    if (i < in.size() && in[i] == 'I') ++i;
    if (i < in.size() && in[i] == 'F') ++i;
    if (i >= in.size()) {
      err = true;
      return false;
    }
    switch (in[i]) {
      case 'A':
      case 'B':
      case 'C':
      case 'D':
        return false;
      case 'Q':
      case 'R':
      case 'S':
      case 'T':
        return true;
    }
    err = true;
    return false;
  }

  void pointer_kind(u8& q, u8& aff) {
    q = 0;
    aff = AFF_POINTER;
    if (eat("$$Q")) {
      aff = AFF_RREF;
      return;
    }
    if (eat("$$R")) {
      aff = AFF_RREF;
      q = Q_VOLATILE;
      return;
    }
    switch (take()) {
      case 'A':
        aff = AFF_REF;
        break;
      case 'B':
        aff = AFF_REF;
        q = Q_VOLATILE;
        break;
      case 'P':
        break;
      case 'Q':
        q = Q_CONST;
        break;
      case 'R':
        q = Q_VOLATILE;
        break;
      case 'S':
        q = Q_CONST | Q_VOLATILE;
        break;
      default:
        err = true;
    }
  }

  u32 pointer() {
    u8 q, aff;
    pointer_kind(q, aff);
    if (err) return 0;
    u32 p = add(NK::Pointer);
    if (!p) return 0;
    n(p).a = q;
    n(p).b = aff;
    u32 pointee;
    if (eat('6')) {
      pointee = function_type(false);
    } else {
      n(p).a |= ext_qualifiers();
      pointee = type(Mode::Mangle);
    }
    if (err) return 0;
    n(p).x = pointee;
    return p;
  }

  u32 member_pointer() {
    u8 q, aff;
    pointer_kind(q, aff);
    if (err) return 0;
    u32 p = add(NK::Pointer);
    if (!p) return 0;
    n(p).a = q | ext_qualifiers();
    n(p).b = aff;
    u32 cls, pointee;
    if (eat('8')) {
      cls = type_name();
      pointee = err ? 0 : function_type(true);
    } else {
      bool member;
      u8 pq = qualifiers(&member);
      if (!err && !member) err = true;
      cls = err ? 0 : type_name();
      pointee = err ? 0 : type(Mode::Drop);
      if (!err) n(pointee).a = pq;
    }
    if (err) return 0;
    n(p).x = pointee;
    n(p).y = cls;
    return p;
  }

  u32 class_type() {
    char c = take();
    u8 tag = 0;
    switch (c) {
      case 'T':
        tag = 2;
        break;
      case 'U':
        tag = 1;
        break;
      case 'V':
        tag = 0;
        break;
      case 'W': {
        char k = take();
        if (k < '0' || k > '7') return fail();
        tag = 3;
        break;
      }
      default:
        return fail();
    }
    u32 qn = type_name();
    if (err) return 0;
    u32 t = add(NK::Tag);
    if (!t) return 0;
    n(t).x = qn;
    n(t).b = tag;
    return t;
  }

  u32 array_type() {
    ++pos;  // 'Y'
    u64 rank = unsigned_number();
    if (err || rank == 0 || rank > 64) return fail();
    u32 head = 0, tail = 0;
    for (u64 k = 0; k < rank && !err; ++k) {
      u32 i = int_node();
      if (i && n(i).a) err = true;  // a negative dimension
      if (!err) append(head, tail, i);
    }
    u8 q = 0;
    if (!err && eat("$$C")) {
      bool member;
      q = qualifiers(&member);
      if (member) err = true;
    }
    u32 elem = err ? 0 : type(Mode::Drop);
    if (err) return 0;
    u32 t = add(NK::Array);
    if (!t) return 0;
    n(t).x = head;
    n(t).y = elem;
    n(t).a = q;
    return t;
  }

  u32 primitive_type() {
    char c = take();
    const char* t = c == '_' ? coded(EXTENDED_PRIMITIVES, take()) : coded(PRIMITIVES, c);
    if (err || !t) return fail();
    u32 i = add(NK::Prim);
    if (i) n(i).s = t;
    return i;
  }

  enum class Mode { Drop, Mangle, Result };

  u32 type(Mode m) {
    Depth d(*this);
    if (err) return 0;
    u8 q = 0;
    if (m == Mode::Mangle)
      q = qualifiers();
    else if (m == Mode::Result && eat('?'))
      q = qualifiers();
    if (err || at_end()) return fail();
    char c = peek();
    u32 t;
    if (c == 'T' || c == 'U' || c == 'V' || c == 'W') {
      t = class_type();
    } else if (pointer_ahead()) {
      bool member = member_pointer_ahead();
      if (err) return 0;
      t = member ? member_pointer() : pointer();
    } else if (c == 'Y') {
      t = array_type();
    } else if (eat("$$A8@@")) {
      t = function_type(true);
    } else if (eat("$$A6")) {
      t = function_type(false);
    } else if (eat("$$T")) {
      t = add(NK::Nullptr);
    } else {
      t = primitive_type();
    }
    if (err || !t) return fail();
    n(t).a |= q;
    return t;
  }

  // a function's parameters: X (void), or types (digits: back references) ending in @, or in Z (variadic)
  u32 parameters(u8& flags) {
    if (eat('X')) return 0;
    u32 head = 0, tail = 0;
    while (!err && peek() != '@' && peek() != 'Z') {
      if (at_end()) return fail();
      if (is_digit(peek())) {
        u32 k = u32(take() - '0');
        if (k >= br.nparams) return fail();
        append(head, tail, br.params[k]);
        continue;
      }
      size_t before = pos;
      u32 t = type(Mode::Drop);
      if (err) return 0;
      append(head, tail, t);
      if (br.nparams <= 9 && pos - before > 1) br.params[br.nparams++] = t;
    }
    if (err) return 0;
    if (eat('@')) return head;
    if (eat('Z')) {
      flags |= F_VARIADIC;
      return head;
    }
    return fail();
  }

  u32 function_type(bool this_quals) {
    Depth d(*this);
    if (err) return 0;
    u8 q = 0, ref = 0;
    if (this_quals) {
      q = ext_qualifiers();
      if (eat('G'))
        ref = 1;
      else if (eat('H'))
        ref = 2;
      q |= qualifiers();
    }
    const char* cc = calling_convention(take());
    if (err || !cc) return fail();
    u32 ret = 0;
    if (!eat('@')) ret = type(Mode::Result);
    if (err) return 0;
    u8 flags = 0;
    u32 params = parameters(flags);
    if (err) return 0;
    if (eat("_E"))
      flags |= F_NOEXCEPT;
    else if (!eat('Z'))
      return fail();
    u32 f = add(NK::Function);
    if (!f) return 0;
    Node& fn = n(f);
    fn.x = ret;
    fn.y = params;
    fn.a = q;
    fn.b = ref;
    fn.c = flags;
    fn.s = cc;
    return f;
  }

  // --- template arguments ---------------------------------------------------------------------------------------

  u32 symbol_ref(u8 address, int offsets) {
    size_t start = pos;
    u32 sym = 0;
    if (peek() == '?') {
      sym = symbol();
      if (err) return 0;
      // the symbol's innermost name counts for back references
      u32 qn = n(sym).x;
      if (qn && n(qn).kind == NK::Qualified) {
        u32 leaf = component(qn, 0);
        memorize(n(leaf).kind == NK::Simple ? n(leaf).s : in.substr(start, pos - start), leaf);
      }
    }
    u32 head = 0, tail = 0;
    for (int k = 0; k < offsets && !err; ++k) append(head, tail, int_node());
    if (err) return 0;
    u32 r = add(NK::SymbolRef);
    if (!r) return 0;
    n(r).x = sym;
    n(r).y = head;
    n(r).b = address;
    return r;
  }

  u32 template_args() {
    u32 head = 0, tail = 0;
    while (!eat('@')) {
      if (at_end() || err) return fail();
      if (eat("$S") || eat("$$V") || eat("$$$V") || eat("$$Z")) continue;  // packs
      u32 a = 0;
      if (eat("$$Y")) {
        u32 qn = type_name();
        a = err ? 0 : add(NK::Tag);
        if (a) n(a).x = qn;
      } else if (eat("$$B")) {
        a = type(Mode::Drop);
      } else if (eat("$$C")) {
        a = type(Mode::Mangle);
      } else if (starts("$1") || starts("$H") || starts("$I") || starts("$J")) {
        ++pos;
        char k = take();
        a = symbol_ref(1, k == 'J' ? 3 : k == 'I' ? 2 : k == 'H' ? 1 : 0);
      } else if (starts("$E?")) {
        pos += 2;
        a = symbol_ref(0, 0);
      } else if (starts("$F") || starts("$G")) {
        ++pos;
        char k = take();
        a = symbol_ref(0, k == 'G' ? 3 : 2);
      } else if (eat("$0")) {
        a = int_node();
      } else if (eat("$D") || eat("$Q")) {  // a template parameter: printed by its number
        a = int_node();
      } else {
        a = type(Mode::Drop);
      }
      if (err || !a) return fail();
      append(head, tail, a);
    }
    return head;
  }

  // --- symbols --------------------------------------------------------------------------------------------------

  // A to X: private, protected, public, eight codes each: plain, static, virtual, virtual with an adjustor (two codes
  // each). Y Z: not a member. 9: extern "C", no type. $[R]0 to $[R]5: a vtordisp thunk, two codes for each access.
  u32 function_class() {
    static constexpr u32 access[] = {FC_PRIVATE, FC_PROTECTED, FC_PUBLIC};
    static constexpr u32 kind[] = {0, FC_STATIC, FC_VIRTUAL, FC_VIRTUAL | FC_ADJUSTOR};
    char c = take();
    if (c >= 'A' && c <= 'X') return access[(c - 'A') / 8] | kind[(c - 'A') / 2 % 4];
    if (c == 'Y' || c == 'Z') return FC_GLOBAL;
    if (c == '9') return FC_EXTERN_C | FC_NO_PARAMS;
    if (c == '$') {
      u32 v = FC_VTORDISP | (eat('R') ? FC_VTORDISP_EX : 0);
      c = take();
      if (c >= '0' && c <= '5') return access[(c - '0') / 2] | FC_VIRTUAL | v;
    }
    err = true;
    return 0;
  }

  u32 function_encoding(u32 qn) {
    u32 fc = 0;
    if (eat("$$J0")) fc |= FC_EXTERN_C;
    if (at_end()) return fail();
    fc |= function_class();
    if (err) return 0;
    u32 head = 0, tail = 0;
    int offsets = fc & FC_ADJUSTOR ? 1 : fc & FC_VTORDISP_EX ? 4 : fc & FC_VTORDISP ? 2 : 0;
    for (int k = 0; k < offsets && !err; ++k) append(head, tail, int_node());
    if (err) return 0;
    u32 sig;
    if (fc & FC_NO_PARAMS) {
      sig = add(NK::Function);
      if (sig) n(sig).c = F_NO_PARAMS;
    } else {
      sig = function_type(!(fc & (FC_GLOBAL | FC_STATIC)));
    }
    if (err || !sig) return fail();
    u32 f = add(NK::FuncSym);
    if (!f) return 0;
    n(f).x = qn;
    n(f).y = sig;
    n(f).z = head;
    n(f).v = fc;
    return f;
  }

  u32 variable_encoding(u32 qn, u8 storage) {
    u32 t = type(Mode::Drop);
    if (err) return 0;
    if (n(t).kind == NK::Pointer) {
      // the storage class's qualifiers are the pointer's own (undname prints those, not the type's)
      u8 ext = ext_qualifiers();
      u8 q = qualifiers();
      if (err) return 0;
      n(t).a = u8((n(t).a & ~(Q_CONST | Q_VOLATILE)) | ext | q);
    } else {
      n(t).a |= qualifiers();
    }
    if (err) return 0;
    u32 v = add(NK::VarSym);
    if (!v) return 0;
    n(v).x = qn;
    n(v).y = t;
    n(v).a = storage;
    return v;
  }

  u32 declarator(bool fresh_local = false) {
    u32 qn = symbol_name(fresh_local);
    if (err) return 0;
    char c = peek();
    u32 sym;
    if (c >= '0' && c <= '4') {
      ++pos;
      sym = variable_encoding(qn, u8(c - '0'));
    } else {
      sym = function_encoding(qn);
      if (!err)
        if (u32 conv = conversion_of(component(qn, 0))) n(conv).x = n(n(sym).y).x;
    }
    if (err) return 0;
    if (u32 conv = conversion_of(component(qn, 0)); conv && !n(conv).x) return fail();
    return sym;
  }

  u32 special_table(const char* name) {
    u32 leaf = text_node(name);
    u32 qn = err ? 0 : scope_chain(leaf);
    if (err) return 0;
    char f = take();
    if (f != '6' && f != '7') return fail();
    u8 q = qualifiers();
    u32 head = 0, tail = 0;
    while (!err && !eat('@')) {
      if (at_end()) return fail();
      append(head, tail, type_name());
    }
    if (err) return 0;
    u32 t = add(NK::Table);
    if (!t) return 0;
    n(t).x = qn;
    n(t).y = head;
    n(t).a = q;
    return t;
  }

  u32 untyped(u32 leaf) {
    u32 qn = err ? 0 : scope_chain(leaf);
    if (err) return 0;
    u32 t = add(NK::Untyped);
    if (t) n(t).x = qn;
    return t;
  }

  u32 string_literal() {
    if (!eat("@_")) return fail();
    char k = take();
    if (k != '0' && k != '1') return fail();
    bool neg;
    number(neg);
    if (err || neg) return fail();
    size_t crc = in.find('@', pos);
    if (crc == std::string_view::npos) return fail();
    pos = crc + 1;
    size_t e = in.find('@', pos);
    if (e == std::string_view::npos) return fail();
    pos = e + 1;
    return add(NK::StrLit);
  }

  u32 init_fini(bool atexit) {
    bool member = eat('?');
    u32 sym = declarator(true);
    if (err) return 0;
    u32 var = n(sym).x;
    u32 fn;
    if (n(sym).kind == NK::VarSym) {
      if (!eat('@') || (member && !eat('@'))) return fail();
      fn = function_encoding(0);
    } else {
      if (member) return fail();
      fn = sym;
    }
    if (err) return 0;
    u32 dyn = add(NK::Dynamic);
    u32 cell = add(NK::List);
    u32 qn = add(NK::Qualified);
    if (!dyn || !cell || !qn) return 0;
    n(dyn).a = atexit;
    n(dyn).x = var;
    n(cell).x = dyn;
    n(qn).x = cell;
    n(qn).v = 1;
    n(fn).x = qn;
    return fn;
  }

  // ?_<code> symbols that are not functions or variables (after the symbol's '?'); 0 without an error otherwise
  u32 special_symbol() {
    if (eat("?_7")) return special_table("`vftable'");
    if (eat("?_8")) return special_table("`vbtable'");
    if (eat("?_S")) return special_table("`local vftable'");
    if (eat("?_R4")) return special_table("`RTTI Complete Object Locator'");
    if (eat("?_R0")) {
      u32 t = type(Mode::Result);
      if (err || !eat("@8")) return fail();
      u32 s = add(NK::TypeDesc);
      if (s) n(s).x = t;
      return s;
    }
    if (eat("?_R1")) {
      u32 head = 0, tail = 0;
      for (int k = 0; k < 4 && !err; ++k) append(head, tail, int_node());
      if (err) return 0;
      u32 leaf = add(NK::BaseDesc);
      if (!leaf) return 0;
      n(leaf).y = head;
      u32 s = untyped(leaf);
      if (!err) eat('8');
      return s;
    }
    if (eat("?_R2") || eat("?_R3")) {
      u32 leaf = text_node(in[pos - 1] == '2' ? "`RTTI Base Class Array'" : "`RTTI Class Hierarchy Descriptor'");
      u32 s = untyped(leaf);
      if (!err && !eat('8')) return fail();
      return s;
    }
    if (eat("?_B") || eat("?__J")) {
      u32 leaf = add(NK::Guard);
      if (!leaf) return 0;
      n(leaf).a = in[pos - 1] == 'J';
      u32 s = untyped(leaf);
      if (err) return 0;
      if (!eat("4IA") && !eat('5')) return fail();
      char c = peek();
      if (is_digit(c) || (c >= 'A' && c <= 'P')) n(leaf).v = unsigned_number();
      return err ? 0 : s;
    }
    if (eat("?_9")) {
      u32 leaf = add(NK::Vcall);
      u32 s = leaf ? untyped(leaf) : 0;
      if (err || !eat("$B")) return fail();
      n(leaf).v = unsigned_number();
      if (err || !eat('A') || !calling_convention(take())) return fail();
      return s;
    }
    if (eat("?_C")) return string_literal();
    if (eat("?__E")) return init_fini(false);
    if (eat("?__F")) return init_fini(true);
    if (starts("?_A") || starts("?_P")) return fail();  // typeof, udt returning: not read
    return 0;
  }

  u32 symbol() {
    Depth d(*this);
    if (err) return 0;
    if (starts("??@")) {  // an MD5-hashed name
      size_t e = in.find('@', pos + 3);
      if (e == std::string_view::npos) return fail();
      u32 m = add(NK::Md5);
      if (m) n(m).s = in.substr(pos, e + 1 - pos);
      pos = e + 1;
      return m;
    }
    if (!eat('?')) return fail();
    u32 s = special_symbol();
    if (s || err) return err ? 0 : s;
    return declarator();
  }

  // --- printing -------------------------------------------------------------------------------------------------

  // appends t as norm_name leaves undname's text: no whitespace next to < > , * &
  void put(std::string_view t) {
    if (t.empty()) return;
    std::string& o = *out;
    size_t i = 0;
    if (!o.empty() && tight(o.back()))
      while (i < t.size() && t[i] == ' ') ++i;
    if (i < t.size() && tight(t[i]))
      while (!o.empty() && o.back() == ' ') o.pop_back();
    o.append(t.data() + i, t.size() - i);
    if (o.size() > MAX_OUTPUT) err = true;
  }
  void put_number(u64 v, bool neg = false) {
    char b[24];
    auto r = std::to_chars(b, b + sizeof b, v);
    if (neg) put("-");
    put(std::string_view(b, size_t(r.ptr - b)));
  }
  void space_if_needed() {
    if (!out->empty() && (is_word(out->back()) || out->back() == '>')) put(" ");
  }
  // "::" after a scope; in a parameter list the scope's last word, or an anonymous namespace, goes with it, as
  // norm_params drops them
  void scope_sep() {
    if (sig) {
      size_t w = out->size();
      if (out->ends_with(ANON))
        w -= ANON.size();
      else
        while (w > 0 && is_word((*out)[w - 1])) --w;
      if (w < out->size()) drops.emplace_back(w, out->size() + 2);
    }
    put("::");
  }
  void quals(u8 q) {
    if (q & Q_CONST) put(" const");
    if (q & Q_VOLATILE) put(" volatile");
    if (q & Q_RESTRICT) put(" __restrict");
    if (q & Q_UNALIGNED) put(" __unaligned");
  }

  void name(u32 qn) {
    Depth d(*this);
    if (err || !qn) return;
    bool first = true;
    for (u32 c = n(qn).x; c && !err; c = n(c).next) {
      if (!first) scope_sep();
      first = false;
      ident(n(c).x);
    }
  }

  void list(u32 head, const char* sep, void (Impl::*item)(u32)) {
    for (u32 c = head; c && !err; c = n(c).next) {
      if (c != head) put(sep);
      (this->*item)(n(c).x);
    }
  }

  void targ(u32 a) {
    Depth d(*this);
    if (err) return;
    const Node& x = n(a);
    switch (x.kind) {
      case NK::Int:
        put_number(x.v, x.a);
        return;
      case NK::SymbolRef: {
        bool braces = x.y != 0;
        if (braces)
          put("{");
        else if (x.b)
          put("&");
        if (x.x) {
          qualified_key(x.x, nullptr);
          if (braces) put(",");
        }
        list(x.y, ",", &Impl::targ);
        if (braces) put("}");
        return;
      }
      default:
        type_full(a);
    }
  }

  void ident(u32 id) {
    Depth d(*this);
    if (err || !id) return;
    const Node& x = n(id);
    switch (x.kind) {
      case NK::Simple:
      case NK::Text:
        put(x.s);
        return;
      case NK::Anon:
        put(ANON);
        return;
      case NK::Template: {
        u32 conv = n(x.x).kind == NK::Conversion ? x.x : 0;  // undname: operator<args> type
        ident(conv ? 0 : x.x);
        if (conv) put("operator");
        put("<");
        list(n(id).y, ",", &Impl::targ);
        put(">");
        if (conv) type_full(n(conv).x);
        return;
      }
      case NK::Local:  // a function's local scope: the function
        qualified_key(x.x, nullptr);
        return;
      case NK::Structor: {  // the class's name, without its template arguments
        if (x.a) put("~");
        u32 cls = x.x;
        ident(n(cls).kind == NK::Template ? n(cls).x : cls);
        return;
      }
      case NK::Conversion:
        put("operator ");
        type_full(x.x);
        return;
      case NK::Dynamic:
        dynamic_name(id, n(x.x).x, false);
        return;
      case NK::Guard:
        put(x.a ? "`local static thread guard'" : "`local static guard'");
        if (x.v) {
          put("{");
          put_number(x.v);
          put("}'");
        }
        return;
      case NK::BaseDesc:
        put("`RTTI Base Class Descriptor at (");
        list(x.y, ",", &Impl::targ);
        put(")'");
        return;
      case NK::Vcall:
        put("`vcall'{");
        put_number(x.v);
        put(",{flat}}'");
        return;
      case NK::LiteralOp:
        put("operator \"\" ");
        put(x.s);
        return;
      default:
        err = true;
    }
  }

  // a dynamic initializer's or atexit destructor's name from the variable's component cell `from` on: the scopes,
  // then the special name, which holds the variable's own name only (as undname prints it). lead: "::" before the
  // first as well
  void dynamic_name(u32 dyn, u32 from, bool lead) {
    for (u32 c = from; c && !err; c = n(c).next) {
      if (lead || c != from) scope_sep();
      if (n(c).next) {
        ident(n(c).x);
        continue;
      }
      put(n(dyn).a ? "`dynamic atexit destructor for '" : "`dynamic initializer for '");
      ident(n(c).x);
      put("''");
    }
  }

  void type_pre(u32 t) {
    Depth d(*this);
    if (err || !t) return;
    const Node& x = n(t);
    switch (x.kind) {
      case NK::Prim:
        put(x.s);
        quals(x.a);
        return;
      case NK::Nullptr:
        if (sig) drops.emplace_back(out->size(), out->size() + 5);
        put("std::nullptr_t");
        quals(x.a);
        return;
      case NK::Tag:
        name(x.x);
        quals(x.a);
        return;
      case NK::Array:
        type_pre(x.y);
        quals(x.a);
        return;
      case NK::Function:
        function_pre(t, false);
        return;
      case NK::Pointer: {
        u32 pointee = x.x;
        NK pk = n(pointee).kind;
        if (pk == NK::Function)
          function_pre(pointee, true);
        else
          type_pre(pointee);
        space_if_needed();
        const Node& p = n(t);
        if (p.a & Q_UNALIGNED) put("__unaligned ");
        if (pk == NK::Array) {
          put("(");
        } else if (pk == NK::Function) {
          put("(");
          if (!is_cdecl(pointee)) {
            put(n(pointee).s);
            put(" ");
          }
        }
        if (p.y) {
          name(p.y);
          scope_sep();
        }
        put(p.b == AFF_POINTER ? "*" : p.b == AFF_REF ? "&" : "&&");
        quals(u8(n(t).a & (Q_CONST | Q_VOLATILE | Q_RESTRICT)));
        return;
      }
      default:
        err = true;
    }
  }

  void type_post(u32 t) {
    Depth d(*this);
    if (err || !t) return;
    const Node& x = n(t);
    switch (x.kind) {
      case NK::Pointer: {
        NK pk = n(x.x).kind;
        if (pk == NK::Function || pk == NK::Array) put(")");
        type_post(x.x);
        return;
      }
      case NK::Function:
        function_post(t);
        return;
      case NK::Array:
        space_if_needed();
        for (u32 c = x.x; c && !err; c = n(c).next) {
          put("[");
          if (n(n(c).x).v) put_number(n(n(c).x).v);
          put("]");
        }
        type_post(n(t).y);
        return;
      default:
        return;
    }
  }

  void type_full(u32 t) {
    type_pre(t);
    type_post(t);
  }

  // __cdecl, the convention of nearly every function, is not printed: `void (*)(int)`, `void(int)`
  bool is_cdecl(u32 f) const { return nodes[f].s == "__cdecl"; }

  // what goes before a function type's parameters, or (pointed) before the `(*` of a pointer to it: the return type,
  // and for the type itself a calling convention other than __cdecl
  void function_pre(u32 f, bool pointed) {
    bool cc = !pointed && !is_cdecl(f);
    if (u32 ret = n(f).x) {
      type_pre(ret);
      if (pointed || cc) put(" ");
    }
    if (cc) put(n(f).s);
  }

  void params(u32 f) {
    const Node& x = n(f);
    put("(");
    if (x.y)
      list(x.y, ",", &Impl::type_full);
    else if (!(x.c & F_VARIADIC))
      put("void");
    if (n(f).c & F_VARIADIC) put(n(f).y ? ",..." : "...");
    put(")");
  }

  void this_qualifiers(u32 f) {
    const Node& x = n(f);
    u8 q = x.a;
    if (q & Q_CONST) put("const");
    if (q & Q_VOLATILE) put(q & Q_CONST ? " volatile" : "volatile");
    if (q & Q_RESTRICT) put(" __restrict");
    if (q & Q_UNALIGNED) put(" __unaligned");
    if (n(f).c & F_NOEXCEPT) put(" noexcept");
    if (n(f).b) put(n(f).b == 1 ? " &" : " &&");
  }

  void function_post(u32 f) {
    if (n(f).c & F_NO_PARAMS) return;
    params(f);
    this_qualifiers(f);
    type_post(n(f).x);
  }

  void thunk_suffix(u32 fsym) {
    u32 fc = u32(n(fsym).v);
    u32 c = n(fsym).z;
    auto num = [&] {
      if (!c) return;
      const Node& i = n(n(c).x);
      put_number(i.v, i.a);
      c = n(c).next;
    };
    if (fc & FC_ADJUSTOR) {
      put("`adjustor{");
      num();
      put("}'");
    } else if (fc & FC_VTORDISP) {
      put(fc & FC_VTORDISP_EX ? "`vtordispex{" : "`vtordisp{");
      for (bool first = true; c && !err; first = false) {
        if (!first) put(",");
        num();
      }
      put("}'");
    }
  }

  void for_list(u32 targets) {
    if (!targets) return;
    put("{for ");
    for (u32 c = targets; c && !err; c = n(c).next) {
      if (c != targets) put("s ");
      put("`");
      name(n(c).x);
      put("'");
    }
    put("}");
  }

  // --- keys -----------------------------------------------------------------------------------------------------

  // the qualified name key of a symbol, appended to *out. A name whose scope is a function's local scope is that
  // function's key and its own name (`f::x`), and *owner_out gets the function's key.
  void qualified_key(u32 s, std::string* owner_out) {
    Depth d(*this);
    if (err) return;
    const Node& x = n(s);
    switch (x.kind) {
      case NK::FuncSym:
      case NK::VarSym:
      case NK::Untyped:
        break;
      case NK::Table: {
        u32 qn = x.x, targets = x.y;
        name(qn);
        for_list(targets);
        return;
      }
      case NK::TypeDesc:
        type_full(x.x);
        put("::`RTTI Type Descriptor'");
        return;
      case NK::StrLit:
        put("`string'");
        return;
      case NK::Md5:
        put(x.s);
        return;
      default:
        err = true;
        return;
    }
    u32 qn = n(s).x;
    u32 leaf = component(qn, 0);
    if (n(leaf).kind == NK::Dynamic) {
      // the variable's scopes up to its last local scope are that scope's function
      u32 cells = n(n(leaf).x).x, local = 0;
      for (u32 c = cells; c; c = n(c).next)
        if (n(n(c).x).kind == NK::Local) local = c;
      if (local) owner_key(n(n(local).x).x, owner_out);
      dynamic_name(leaf, local ? n(local).next : cells, local != 0);
      return;
    }
    u32 parent = component(qn, 1);
    if (parent && n(parent).kind == NK::Local) {
      owner_key(n(parent).x, owner_out);
      scope_sep();
      ident(leaf);
    } else {
      name(qn);
    }
    if (n(s).kind == NK::FuncSym) thunk_suffix(s);
  }

  // the key of a local scope's function, appended to *out and copied to *owner_out
  void owner_key(u32 fn, std::string* owner_out) {
    size_t from = out->size();
    qualified_key(fn, nullptr);
    if (owner_out) owner_out->assign(*out, from, std::string::npos);
  }

  bool keys(std::string_view d, NameKeys& k) {
    // not a C++ name; an MD5-hashed one; one whose name is another decorated name (`??x$initializer$@...`)
    if (d.empty() || d[0] != '?' || d.starts_with("??@") ||
        (d.size() > 2 && d[1] == '?' && d[2] >= 'a' && d[2] <= 'z')) {
      k = {d, {}, d};
      return true;
    }
    if (d.starts_with("??_C@")) {  // a string literal: compared by value, every one the same name
      k = {"`string'", {}, "`string'"};
      return true;
    }
    reset(d);
    u32 s = symbol();
    if (err || !s || pos != in.size()) {
      k = {d, {}, d};
      return false;
    }
    qual.clear();
    owner.clear();
    sigbuf.clear();
    out = &qual;
    sig = false;
    qualified_key(s, &owner);  // the owner stays empty unless the name is in a function's local scope
    if (!err && n(s).kind == NK::FuncSym && !(n(n(s).y).c & F_NO_PARAMS)) {
      out = &sigbuf;
      sig = true;
      drops.clear();
      params(n(s).y);
      sig = false;
      apply_drops();
    }
    if (err) {
      k = {d, {}, d};
      return false;
    }
    k.qualified = qual;
    k.signature = sigbuf;
    k.owner = owner.empty() ? std::string_view(qual) : std::string_view(owner);
    return true;
  }

  // norm_params on the parameter list: the `word::` scopes dropped, no space inside the parentheses' ends, () as
  // (void)
  void apply_drops() {
    std::string& s = sigbuf;
    if (!drops.empty()) {
      size_t w = 0, r = 0;
      for (auto [a, b] : drops) {
        if (a < r) a = r;
        while (r < a) s[w++] = s[r++];
        r = b > r ? b : r;
      }
      while (r < s.size()) s[w++] = s[r++];
      s.resize(w);
    }
    if (s.find("( ") != std::string::npos || s.find(" )") != std::string::npos)
      s = replace_all(replace_all(s, "( ", "("), " )", ")");
    if (s == "()") s = "(void)";
  }
};

Demangler::Demangler() : impl_(std::make_unique<Impl>()) {}
Demangler::~Demangler() = default;

bool Demangler::keys(std::string_view decorated, NameKeys& out) { return impl_->keys(decorated, out); }

}  // namespace verifier
