// PE images (the original and the rebuilt DLL): the memory-mapped image, sections, .pdata, base relocations,
// imports, unwind data and the POGO debug entry.
#pragma once
#include <algorithm>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "util.hpp"

namespace verifier {

constexpr u32 SCN_EXEC = 0x20000000, SCN_WRITE = 0x80000000;
constexpr u64 MAX_DATA_COMPARE = 0x1000;

struct Section {
  u64 lo, hi;
  u32 ch;
};

struct Import {
  std::string dll;      // lower case
  std::string name;     // empty when by ordinal
  u32 ordinal = 0;
  bool operator==(const Import& o) const { return dll == o.dll && name == o.name && ordinal == o.ordinal; }
};

struct Unwind {
  Bytes body;                      // header + unwind codes
  std::optional<u64> handler, hdata;
  bool has_chain = false;
  u32 chain_begin = 0, chain_end = 0, chain_unwind = 0;   // RVAs
};

class Image {
 public:
  static Image load(const std::string& path);
  static Image from_parts(u64 base, std::string mem, std::vector<Section> sections,
                          std::map<u64, std::pair<u64, u32>> pdata, std::vector<u64> relocs,
                          std::unordered_map<u64, Import> imports);

  u64 base = 0;
  std::string img;                       // the memory-mapped image (offset = VA - base)
  std::vector<Section> sections;
  std::map<u64, std::pair<u64, u32>> pdata;   // begin VA -> (end VA, UNWIND_INFO RVA); first entry wins
  std::vector<u64> pdata_sorted;
  std::vector<u64> reloc_sorted;          // the 64-bit relocation sites, sorted, distinct
  std::unordered_map<u64, Import> imports;   // IAT slot VA -> import
  std::map<std::string, std::pair<u64, u64>> pogo;   // subsection -> (start VA, end VA)

  std::vector<u64> pdata_in(u64 lo, u64 hi) const;
  std::string_view bytes(u64 va, i64 n) const;   // short (or empty) past the end of the image
  u32 u32_at(u64 va) const;
  i32 i32_at(u64 va) const;
  u64 u64_at(u64 va) const;
  std::optional<u32> flags(u64 va) const;
  bool executable(u64 va) const;
  bool writable(u64 va) const;
  Bytes cstring(u64 va, bool wide = false) const;
  std::optional<u64> extent(u64 va) const;   // .pdata range plus chained ranges
  Unwind unwind(u32 unwind_rva) const;
  bool has_reloc(u64 va) const { return std::binary_search(reloc_sorted.begin(), reloc_sorted.end(), va); }
  size_t reloc_lower_bound(u64 va) const;

 private:
  void finish();
};

std::optional<u64> leaf_extent(const Image& img, u64 va);   // in x64.cpp: needs the decoder

// Comparable signatures of RTTI / EH structures
Bytes type_name(const Image& img, u64 td);
Bytes gs_data(const Image& img, u64 va);
struct BaseDesc {
  Bytes name;
  u32 ncont; i32 mdisp, pdisp, vdisp; u32 attr;
  bool operator==(const BaseDesc& o) const = default;
};
struct Rtti {
  bool present = false;      // a CompleteObjectLocator in a section
  bool bad_sig = false; u32 sig = 0;
  u32 off = 0, cdoff = 0, attrs = 0;
  Bytes name;
  std::vector<BaseDesc> bases;
};
Rtti rtti(const Image& img, u64 col);
struct CatchableSig {
  u32 props; Bytes name; i32 mdisp, pdisp, vdisp, size;
  bool operator==(const CatchableSig& o) const = default;
};
struct ThrowInfoSig {
  u32 attrs;
  std::vector<CatchableSig> types;
  std::vector<u64> funcs;   // destructor, then each type's copy constructor (0 when absent)
};
ThrowInfoSig throw_info(const Image& img, u64 ti);
std::string imp_str(const Import* imp);

}  // namespace verifier
