// The MSVC x64 exception-handling and RTTI records, described once as layouts: each field's offset and what it
// holds. The comparison walks them generically (compare_eh.cpp for the handler data, signature() for RTTI and
// ThrowInfo); the problem messages are part of the layouts.
//
// Only the fixed-layout records of __CxxFrameHandler3 (FuncInfo version 1-3), __GSHandlerCheck(_EH) and
// __C_specific_handler are described. __CxxFrameHandler4's FuncInfo4 is compressed (variable-length integers, tables
// found through it rather than at fixed offsets): it needs a decoder of its own feeding the same comparisons, see
// Handler::CxxFrame4.
#pragma once
#include <limits>
#include <string>
#include <string_view>
#include <vector>

#include "pe.hpp"

namespace verifier {

struct Layout;

// What a 32-bit field holds. RVAs are relative to the image base.
enum class Holds : u8 {
  Value,     // a value, compared as it is
  Count,     // a value, compared as it is, and the number of entries of a table the record holds or points to
  Type,      // a type descriptor's RVA (0: none), compared by its decorated name
  Function,  // a function's RVA (0: none), compared as a reference
  Funclet,   // handler code's RVA (0: none): a funclet of the function, compared as a function of its own
  Filter,    // an SEH filter: a constant below 0x10 (EXCEPTION_EXECUTE_HANDLER and the like), else a funclet's RVA
  Ip,        // a code address's RVA, compared by its place: an offset in the function or in one of its funclets
  Begin,     // the start of a code range (RVA): an offset in the function
  End,       // the end of a code range (RVA): an offset in the function, or its end
  Target,    // a code address's RVA (0: none), compared by its offset in the function
  Record,    // a record's RVA (0: none): the `layout` record there
  Table,     // a table's RVA: as many entries of `layout` as the Count field at `count_at` says
  Inline,    // a table in the record itself, from this offset on: as many entries as the Count field says
};
// Comparing two records: their Value and Count fields first (any difference is the record's `differs`), then the
// counts against their range, then the other fields in the order listed. A field that differs is reported with its
// own message and ends the comparison of its record, except a Record field whose presence differs (only the record
// it points to is left out). Funclets report their own problems.

struct Member {
  u8 off;
  Holds holds;
  const char* differs = nullptr;   // the message when this field differs ("{}": the entry's index)
  const Layout* layout = nullptr;  // Record, Table, Inline
  int count_at = -1;               // Table, Inline: the offset of the Count field (in this record, listed before)
  bool sign = false;               // a signed value: a negative count is none, a negative RVA reaches back
  // Count: the values allowed; past them the record is out of range, or (clamp) the table is cut there
  i64 lo = std::numeric_limits<i64>::min(), hi = std::numeric_limits<i64>::max();
  bool clamp = false;
  u32 expect = 0;  // Value with `guard`: the value the rest of the record depends on
  bool guard = false;
};

struct Layout {
  const char* name;
  u8 size;  // a table entry's stride
  std::vector<Member> fields;
  const char* differs = nullptr;       // the message when a Value or Count field differs ("{}": the entry's index)
  const char* out_of_range = nullptr;  // the message when a count is out of range (nullptr: `differs`)
  bool stop_at_first = false;          // a table of these stops at its first differing entry (reported once)
};

// the layouts
extern const Layout FUNC_INFO;    // __CxxFrameHandler3's FuncInfo with its unwind map, try blocks, IP-to-state map
extern const Layout SCOPE_TABLE;  // __C_specific_handler's scope table
extern const Layout COMPLETE_OBJECT_LOCATOR;  // a vtable's RTTI, with its class hierarchy
extern const Layout THROW_INFO;               // a thrown type with its catchable types

// The language-specific handlers whose data is compared, by name
enum class Handler : u8 {
  Unknown,
  CxxFrame3,  // __CxxFrameHandler3: a FuncInfo RVA
  GS,         // __GSHandlerCheck: GS cookie data
  GS_EH,      // __GSHandlerCheck_EH: a FuncInfo RVA, then GS cookie data
  CSpecific,  // __C_specific_handler: a scope table
  CxxFrame4,  // __CxxFrameHandler4 / __GSHandlerCheck_EH4: FuncInfo4, not described (reported as not verifiable)
};
Handler handler_named(std::string_view name);

// Comparable contents of a record and what it points to, read from one image: the values in walk order (for each
// Type and Record field whether it is there), the type names, and the functions (0: none)
struct Signature {
  std::vector<u32> values;
  std::vector<Bytes> names;
  std::vector<u64> functions;
};
Signature signature(const Image& img, const Layout& layout, u64 at);
// a vtable's RTTI from its CompleteObjectLocator's VA (0, or outside the sections: none)
Signature rtti_signature(const Image& img, u64 col);

Bytes type_name(const Image& img, u64 td);  // a type descriptor's decorated name
Bytes gs_data(const Image& img, u64 va);    // GS cookie data: its flags, and the offsets the flags say follow

// the `{}` in a message replaced by the index
std::string message(const char* text, i64 index);

}  // namespace verifier
