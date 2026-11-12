#include "layouts.hpp"

#include <algorithm>

namespace verifier {

using H = Holds;

// -- __CxxFrameHandler3 ------------------------------------------------------------------------------------------

namespace {

// HandlerType: a catch block
const Layout HANDLER{.name = "HandlerType",
                     .size = 20,
                     .fields = {{.off = 0, .holds = H::Value},   // adjectives
                                {.off = 8, .holds = H::Value},   // catch object displacement
                                {.off = 16, .holds = H::Value},  // establisher frame displacement
                                {.off = 4, .holds = H::Type, .differs = "catch type {} differs"},
                                {.off = 12, .holds = H::Funclet}},
                     .differs = "catch handler {} differs"};

// UnwindMapEntry: the state to unwind to and the funclet that does it
const Layout UNWIND_ENTRY{.name = "UnwindMapEntry",
                          .size = 8,
                          .fields = {{.off = 0, .holds = H::Value}, {.off = 4, .holds = H::Funclet}},
                          .differs = "unwind map entry {} differs"};

// TryBlockMapEntry: the try's states, the catch's highest state, and its catch blocks
const Layout TRY_BLOCK{.name = "TryBlockMapEntry",
                       .size = 20,
                       .fields = {{.off = 0, .holds = H::Value},
                                  {.off = 4, .holds = H::Value},
                                  {.off = 8, .holds = H::Value},
                                  {.off = 12, .holds = H::Count, .sign = true},
                                  {.off = 16, .holds = H::Table, .layout = &HANDLER, .count_at = 12}},
                       .differs = "try block {} differs"};

// IPtoStateMapEntry: from this code address on, this state
const Layout IP_ENTRY{.name = "IPtoStateMapEntry",
                      .size = 8,
                      .fields = {{.off = 4, .holds = H::Value}, {.off = 0, .holds = H::Ip}},
                      .differs = "IP-to-state entry {} differs",
                      .stop_at_first = true};

// ESTypeList: the types a dynamic exception specification allows
const Layout ES_LIST{.name = "ESTypeList",
                     .size = 8,
                     .fields = {{.off = 0, .holds = H::Count, .sign = true, .lo = 0, .hi = 0x100},
                                {.off = 4, .holds = H::Table, .layout = &HANDLER, .count_at = 0}},
                     .differs = "exception specification differs"};

}  // namespace

// The tables are compared in the order listed: the IP-to-state map last, its addresses placed in the funclets the
// others name
const Layout FUNC_INFO{.name = "FuncInfo",
                       .size = 40,
                       .fields = {{.off = 0, .holds = H::Value},                               // magic number (version)
                                  {.off = 4, .holds = H::Count, .sign = true, .hi = 0x10000},  // max state
                                  {.off = 12, .holds = H::Count, .hi = 0x10000},               // try blocks
                                  {.off = 20, .holds = H::Count, .hi = 0x100000},              // IP-to-state entries
                                  {.off = 28, .holds = H::Value},  // displacement of the unwind help
                                  {.off = 36, .holds = H::Value},  // flags
                                  {.off = 8, .holds = H::Table, .layout = &UNWIND_ENTRY, .count_at = 4},
                                  {.off = 16, .holds = H::Table, .layout = &TRY_BLOCK, .count_at = 12},
                                  {.off = 32,
                                   .holds = H::Record,
                                   .differs = "exception specification presence differs",
                                   .layout = &ES_LIST},
                                  {.off = 24, .holds = H::Table, .layout = &IP_ENTRY, .count_at = 20}},
                       .differs = "FuncInfo header differs",
                       .out_of_range = "FuncInfo out of range"};

// -- __C_specific_handler ----------------------------------------------------------------------------------------

namespace {

// a scope: the code range it covers, its handler (or filter) and where execution resumes
const Layout SCOPE_ENTRY{.name = "C_SCOPE_TABLE entry",
                         .size = 16,
                         .fields = {{.off = 0, .holds = H::Begin, .differs = "scope {} range differs"},
                                    {.off = 4, .holds = H::End, .differs = "scope {} range differs"},
                                    {.off = 12, .holds = H::Target, .differs = "scope {} target differs"},
                                    {.off = 8, .holds = H::Filter, .differs = "scope {} filter differs"}}};

}  // namespace

const Layout SCOPE_TABLE{.name = "C_SCOPE_TABLE",
                         .size = 4,
                         .fields = {{.off = 0, .holds = H::Count, .hi = 0x1000},
                                    {.off = 4, .holds = H::Inline, .layout = &SCOPE_ENTRY, .count_at = 0}},
                         .differs = "scope table size differs"};

// -- RTTI --------------------------------------------------------------------------------------------------------

namespace {

const Layout BASE_CLASS{.name = "RTTIBaseClassDescriptor",
                        .size = 28,
                        .fields = {{.off = 0, .holds = H::Type},
                                   {.off = 4, .holds = H::Value},     // contained bases
                                   {.off = 8, .holds = H::Value},     // member displacement
                                   {.off = 12, .holds = H::Value},    // vbtable displacement
                                   {.off = 16, .holds = H::Value},    // displacement in the vbtable
                                   {.off = 20, .holds = H::Value}}};  // attributes

const Layout BASE_CLASS_ENTRY{
    .name = "RTTIBaseClassArray entry", .size = 4, .fields = {{.off = 0, .holds = H::Record, .layout = &BASE_CLASS}}};

const Layout CLASS_HIERARCHY{.name = "RTTIClassHierarchyDescriptor",
                             .size = 16,
                             .fields = {{.off = 4, .holds = H::Value},  // attributes
                                        {.off = 8, .holds = H::Count, .hi = 256, .clamp = true},
                                        {.off = 12, .holds = H::Table, .layout = &BASE_CLASS_ENTRY, .count_at = 8}}};

}  // namespace

// a signature other than 1 (not the x64 form): only the signature is compared
const Layout COMPLETE_OBJECT_LOCATOR{.name = "RTTICompleteObjectLocator",
                                     .size = 24,
                                     .fields = {{.off = 0, .holds = H::Value, .expect = 1, .guard = true},
                                                {.off = 4, .holds = H::Value},  // vftable offset in the class
                                                {.off = 8, .holds = H::Value},  // constructor displacement offset
                                                {.off = 12, .holds = H::Type},
                                                {.off = 16, .holds = H::Record, .layout = &CLASS_HIERARCHY}}};

// -- ThrowInfo ---------------------------------------------------------------------------------------------------

namespace {

const Layout CATCHABLE_TYPE{.name = "CatchableType",
                            .size = 28,
                            .fields = {{.off = 0, .holds = H::Value},  // properties
                                       {.off = 4, .holds = H::Type, .sign = true},
                                       {.off = 8, .holds = H::Value},        // member displacement
                                       {.off = 12, .holds = H::Value},       // vbtable displacement
                                       {.off = 16, .holds = H::Value},       // displacement in the vbtable
                                       {.off = 20, .holds = H::Value},       // size
                                       {.off = 24, .holds = H::Function}}};  // copy constructor

const Layout CATCHABLE_ENTRY{.name = "CatchableTypeArray entry",
                             .size = 4,
                             .fields = {{.off = 0, .holds = H::Record, .layout = &CATCHABLE_TYPE}}};

const Layout CATCHABLE_ARRAY{.name = "CatchableTypeArray",
                             .size = 4,
                             .fields = {{.off = 0, .holds = H::Count, .hi = 64, .clamp = true},
                                        {.off = 4, .holds = H::Inline, .layout = &CATCHABLE_ENTRY, .count_at = 0}}};

}  // namespace

const Layout THROW_INFO{.name = "ThrowInfo",
                        .size = 16,
                        .fields = {{.off = 0, .holds = H::Value},                   // attributes
                                   {.off = 4, .holds = H::Function, .sign = true},  // destructor
                                   {.off = 12, .holds = H::Record, .layout = &CATCHABLE_ARRAY}}};

// -- reading -----------------------------------------------------------------------------------------------------

Handler handler_named(std::string_view name) {
  if (name == "__CxxFrameHandler3") return Handler::CxxFrame3;
  if (name == "__GSHandlerCheck") return Handler::GS;
  if (name == "__GSHandlerCheck_EH") return Handler::GS_EH;
  if (name == "__C_specific_handler") return Handler::CSpecific;
  if (name == "__CxxFrameHandler4" || name == "__GSHandlerCheck_EH4") return Handler::CxxFrame4;
  return Handler::Unknown;
}

namespace {

struct Walk {
  const Image& img;
  Signature& s;
  bool stopped = false;  // a guard did not hold

  void record(const Layout& l, u64 at) {
    std::vector<std::pair<int, i64>> counts;  // (offset, entries)
    for (auto& f : l.fields) {
      if (stopped) return;
      u32 raw = img.u32_at(at + f.off);
      u64 target = img.base + u64(f.sign ? i64(i32(raw)) : i64(raw));
      switch (f.holds) {
        case H::Count: {
          i64 n = count_value(f, raw);
          s.values.push_back(u32(n));
          counts.emplace_back(f.off, n);
          break;
        }
        case H::Type:
          s.values.push_back(raw != 0);
          if (raw) s.names.push_back(type_name(img, target));
          break;
        case H::Function:
          s.functions.push_back(raw ? target : 0);
          break;
        case H::Record:
          s.values.push_back(raw != 0);
          if (raw) record(*f.layout, target);
          break;
        case H::Table:
        case H::Inline: {
          i64 n = 0;
          for (auto& [off, c] : counts)
            if (off == f.count_at) n = c;
          u64 first = f.holds == H::Table ? target : at + f.off;
          for (i64 i = 0; i < n && !stopped; ++i) record(*f.layout, first + u64(f.layout->size) * u64(i));
          break;
        }
        default:  // Value, and the code kinds (not in the layouts read here): the value
          s.values.push_back(raw);
          if (f.guard && raw != f.expect) stopped = true;
          break;
      }
    }
  }

  // a Count field's entries: none when negative, cut at its range's end when it clamps
  static i64 count_value(const Member& f, u32 raw) {
    i64 v = f.sign ? i64(i32(raw)) : i64(raw);
    if (f.clamp) v = std::min(v, f.hi);
    return std::max<i64>(v, 0);
  }
};

}  // namespace

Signature signature(const Image& img, const Layout& layout, u64 at) {
  Signature s;
  Walk{img, s}.record(layout, at);
  return s;
}

Signature rtti_signature(const Image& img, u64 col) {
  if (!col || !img.flags(col)) return Signature{{0}, {}, {}};
  Signature s{{1}, {}, {}};
  Walk{img, s}.record(COMPLETE_OBJECT_LOCATOR, col);
  return s;
}

Bytes type_name(const Image& img, u64 td) { return img.cstring(td + 16); }

Bytes gs_data(const Image& img, u64 va) {
  u32 f = img.u32_at(va);
  return Bytes(img.bytes(va, (f & 4) ? 12 : 4));
}

std::string message(const char* text, i64 index) {
  std::string s(text);
  size_t at = s.find("{}");
  if (at != std::string::npos) s.replace(at, 2, std::to_string(index));
  return s;
}

}  // namespace verifier
