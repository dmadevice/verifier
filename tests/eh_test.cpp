// The handler data: each record of a FuncInfo and a scope table, one field changed, and the problem it gives.
#include <functional>
#include <string>

#include "support.hpp"

namespace verifier::test {

namespace {

struct EhBuilt {
  u64 f, end, handler;
};
u32 rva_of(u64 va) { return u32(va - BASE); }

// a 4-byte function whose unwind info names a handler: the handler's code, and the handler data after the handler's
// RVA (`data` given the function's address)
EhBuilt with_handler(Side& s, const std::function<Bytes(u64 f)>& data) {
  u64 handler = s.put(TEXT, unhex("c3"));
  u64 f = s.put(TEXT, unhex("909090c3"));
  Bytes d = data(f);
  u64 u = s.put(RDATA, Bytes{char(1 | (1 << 3)), 0, 0, 0} + le32b(rva_of(handler)) + d, 4);
  s.pdata[f] = {f + 4, rva_of(u)};
  return {f, f + 4, handler};
}

// __CxxFrameHandler3's FuncInfo: one state, one try block with one catch (of a type when `typed`), one IP-to-state
// entry, and an exception specification of `es` catches when `es` is not negative
struct CxxSpec {
  u32 max_state = 1, try_high = 0, disp = 0, ip_off = 0;
  bool typed = true;
  int es = -1;
};
EhBuilt cxx_function(Side& s, const CxxSpec& e) {
  u64 td = s.put(RDATA, Bytes(16, '\0') + Bytes(".?AVWidget@@\0", 13), 8);
  return with_handler(s, [&](u64 f) {
    u64 handlers = s.put(RDATA, le32b(0) + le32b(e.typed ? rva_of(td) : 0) + le32b(e.disp) + le32b(0) + le32b(0), 4);
    u64 unwind_map = s.put(RDATA, le32b(u32(-1)) + le32b(0), 4);
    u64 tries = s.put(RDATA, le32b(0) + le32b(0) + le32b(e.try_high) + le32b(1) + le32b(rva_of(handlers)), 4);
    u64 ips = s.put(RDATA, le32b(rva_of(f + e.ip_off)) + le32b(u32(-1)), 4);
    u32 es = e.es < 0 ? 0 : rva_of(s.put(RDATA, le32b(u32(e.es)) + le32b(rva_of(handlers)), 4));
    u64 fi = s.put(RDATA,
                   le32b(0x19930522) + le32b(e.max_state) + le32b(rva_of(unwind_map)) + le32b(1) +
                       le32b(rva_of(tries)) + le32b(1) + le32b(rva_of(ips)) + le32b(0) + le32b(es) + le32b(0),
                   4);
    return le32b(rva_of(fi));
  });
}

// __C_specific_handler's scope table: `count` scopes (the first written), over the function from `begin` to its end,
// with a filter constant and a target
struct ScopeSpec {
  u32 count = 1, begin = 0, filter = 1, target = 2;
};
EhBuilt seh_function(Side& s, const ScopeSpec& e) {
  return with_handler(s, [&](u64 f) {
    return le32b(e.count) + le32b(rva_of(f + e.begin)) + le32b(rva_of(f + 4)) + le32b(e.filter) +
           le32b(rva_of(f + e.target));
  });
}

template <class Spec>
Problems handler_case(EhBuilt (*build)(Side&, const Spec&), const Spec& os, const Spec& rs, const char* handler) {
  Side o(0), r(0x240);
  EhBuilt a = build(o, os), b = build(r, rs);
  Image O = o.image(), R = r.image();
  NameMap names{{a.handler, handler}};
  Comparer c(
      &O, &R, [&](u64 t) { return t == b.handler ? Key::of_va(a.handler) : Key::named(Key::UNRESOLVED, hex(t)); },
      nullptr, name_of(names));
  return c.check(a.f, a.end, b.f, b.end);
}

Findings handler_records() {
  Findings bad;
  auto expect = [&](const std::string& what, const Problems& got, const std::string& want) {
    std::string g = got.empty() ? "" : got[0].text();
    if (g != want || got.size() > 1) bad.push_back({"eh", what + ": " + (got.empty() ? "nothing" : g)});
  };
  auto cxx = [](const CxxSpec& o, const CxxSpec& r) { return handler_case(cxx_function, o, r, "__CxxFrameHandler3"); };
  CxxSpec same;
  expect("FuncInfo, the same", cxx(same, same), "");
  CxxSpec many = same;
  many.max_state = 0x20000;
  expect("too many states", cxx(many, many), "eh: FuncInfo out of range");
  CxxSpec other = same;
  other.max_state = 2;
  expect("other state count", cxx(same, other), "eh: FuncInfo header differs");
  other = same;
  other.try_high = 1;
  expect("try block", cxx(same, other), "eh: try block 0 differs");
  other = same;
  other.disp = 8;
  expect("catch handler", cxx(same, other), "eh: catch handler 0 differs");
  other = same;
  other.typed = false;
  expect("catch type", cxx(same, other), "eh: catch type 0 differs");
  other = same;
  other.ip_off = 2;
  expect("IP-to-state entry", cxx(same, other), "eh: IP-to-state entry 0 differs");
  CxxSpec es = same;
  es.es = 1;
  expect("exception specification, the same", cxx(es, es), "");
  expect("exception specification presence", cxx(same, es), "eh: exception specification presence differs");
  other = es;
  other.es = 2;
  expect("exception specification", cxx(es, other), "eh: exception specification differs");
  auto seh = [](const ScopeSpec& o, const ScopeSpec& r) {
    return handler_case(seh_function, o, r, "__C_specific_handler");
  };
  ScopeSpec scope;
  expect("scope table, the same", seh(scope, scope), "");
  ScopeSpec diff = scope;
  diff.count = 2;
  expect("scope count", seh(scope, diff), "eh: scope table size differs");
  diff = scope;
  diff.begin = 1;
  expect("scope range", seh(scope, diff), "eh: scope 0 range differs");
  diff = scope;
  diff.target = 3;
  expect("scope target", seh(scope, diff), "eh: scope 0 target differs");
  diff = scope;
  diff.filter = 0;
  expect("scope filter", seh(scope, diff), "eh: scope 0 filter differs");
  expect("unknown handler", handler_case(seh_function, scope, scope, "__CxxFrameHandler4"),
         "eh: handler __CxxFrameHandler4 data is not verifiable");
  return bad;
}

}  // namespace

void add_eh_cases(Cases& cases) {
  cases.insert(cases.end(), {
                                {"handler data records", nullptr, handler_records},
                            });
}

}  // namespace verifier::test
