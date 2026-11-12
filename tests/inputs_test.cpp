// The inputs: decoding, extents, the rebuild's symbols, data items, PE layout, annotations.
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

Findings leaf_extent_case() {
  std::string mov = unhex("b801000000");
  auto times = [](const std::string& s, int n) {
    std::string r;
    for (int i = 0; i < n; ++i) r += s;
    return r;
  };
  std::vector<std::pair<std::string, std::optional<u64>>> cases = {
      {times(mov, 20) + unhex("c3"), TEXT + 101},
      {unhex("7466") + times(mov, 20) + unhex("c390c3"), TEXT + 105},
      {times(mov, 14) + unhex("06c3"), std::nullopt},
  };
  Findings bad;
  for (auto& [code, want] : cases) {
    Bytes mem(END, '\0');
    mem.replace(TEXT, code.size(), code);
    Image img = Image::from_parts(BASE, mem, sections(), {}, {}, {});
    auto got = leaf_extent(img, BASE + TEXT);
    std::optional<u64> w = want ? std::optional<u64>(BASE + *want) : std::nullopt;
    if (got != w) bad.push_back({"leaf extent", hex_bytes(code).substr(0, 24) + ": " + (got ? hex(*got) : "None")});
  }
  return bad;
}

// the same code decoded at two addresses: sizes, mnemonics, absolute branch targets and RIP-relative operands
// follow from the encoding
Findings decode_case() {
  Bytes code = unhex("e8f0ffffff7405e2fc488d0d10000000ff2510000000e9a0ffffffb801000000c3");
  struct Want {
    int size;
    const char* mnemonic;
    i64 target;
  };  // target: branch target or RIP displacement
  std::vector<Want> want = {{5, "call", -0x10}, {2, "jz", 5},      {2, "loop", -4}, {7, "lea", 0x10},
                            {6, "jmp", 0x10},   {5, "jmp", -0x60}, {5, "mov", 0},   {1, "ret", 0}};
  Findings bad;
  for (u64 address : {u64(0x180001000), u64(0x180123f30)}) {
    auto insns = decode_linear(code, address);
    bool ok = insns.size() == want.size();
    u64 at = address;
    for (size_t i = 0; ok && i < insns.size(); ++i) {
      const Insn& x = insns[i];
      const Want& w = want[i];
      u64 next = at + u64(w.size);
      ok = x.address == at && x.size == w.size && x.mnemonic == w.mnemonic;
      if (ok && x.branches() && !x.ops.empty() && x.ops[0].type == OP_IMM) ok = x.ops[0].imm() == i64(next) + w.target;
      if (ok && !x.ops.empty() && x.ops[x.ops.size() - 1].type == OP_MEM)
        ok = x.ops[x.ops.size() - 1].base() == reg_rip() && x.ops[x.ops.size() - 1].disp() == w.target;
      at = next;
    }
    if (!ok) bad.push_back({"decode", "at " + hex(address)});
  }
  return bad;
}

Findings containing_reach() {
  // a large table with one symbol: every offset into it stays that symbol's, up to the next symbol
  FakeRebuilt reb;
  reb.symbols = symbols_at({BASE, BASE + 0x40000});
  Findings bad;
  if (reb.containing(BASE + 0x1c000) != BASE) bad.push_back({"containing", "inside a table past 64 KB"});
  if (reb.containing(BASE + 0x3ffff) != BASE) bad.push_back({"containing", "last byte before the next symbol"});
  if (reb.containing(BASE + 0x40000) != BASE + 0x40000) bad.push_back({"containing", "at the next symbol"});
  if (reb.containing(BASE + 0x40000 + MAX_SYM_OFFSET)) bad.push_back({"containing", "past the limit"});
  if (reb.containing(BASE - 1)) bad.push_back({"containing", "before the first symbol"});
  return bad;
}

Findings span_before_vftable() {
  // a table followed by a vftable ends at the vftable's RTTI locator slot, the 8 bytes before its symbol
  FakeRebuilt reb;
  reb.symbols = Symbols({{BASE, "?table@@3PAY0A@P6AXXZB"},
                         {BASE + 0x20, "??_7Widget@@6B@"},
                         {BASE + 0x40, "?other@@3PAY0A@P6AXXZB"},
                         {BASE + 0x60, "?data@@3HA"}});
  Findings bad;
  if (reb.span(BASE) != 0x18) bad.push_back({"span", "table runs into the vftable's locator slot"});
  if (reb.span(BASE + 0x20) != 0x20) bad.push_back({"span", "vftable"});
  if (reb.span(BASE + 0x40) != 0x20) bad.push_back({"span", "table before plain data"});
  if (reb.span(BASE + 0x18) != 0x8) bad.push_back({"span", "the locator slot itself"});
  return bad;
}

// the data items: every item ends the object before it, the alignment ones are padding, in either JSON layout
Findings data_items_load() {
  namespace fs = std::filesystem;
  fs::path d = fs::temp_directory_path() / ("verifier-items-" + unique_suffix());
  fs::create_directories(d);
  std::string items = (d / "data_items.jsonl").string();
  std::ofstream(items, std::ios::binary) << "{\"ea\": 4096, \"size\": 10, \"kind\": \"string\"}\n"
                                         << "{\"ea\": 4106, \"size\": 2, \"kind\": \"align\"}\n"
                                         << "\n"
                                         << "{\"kind\": \"data\", \"size\": 4, \"ea\": 4108}\n"
                                         << "{\"ea\": 4112, \"size\": 8, \"kind\": \"data\"}\n";
  Original o;
  o.load_items(items, (d / "absent.jsonl").string());
  std::error_code ec;
  fs::remove_all(d, ec);
  Findings bad;
  if (o.object_end(4096) != 4106 || o.object_end(4100) != 4106) bad.push_back({"items", "a string's end"});
  if (o.object_end(4108) != 4112) bad.push_back({"items", "a data item (other key order) ends at the next one"});
  if (o.object_end(4112) != 4112) bad.push_back({"items", "the last item's end is unknown"});
  if (!o.in_padding(4107) || o.in_padding(4100) || o.in_padding(4108)) bad.push_back({"items", "padding"});
  return bad;
}

// a two-section PE file at `base`: code and data, no zero bytes in them
Bytes pe_file(u64 base) {
  auto put = [](Bytes& b, size_t at, u64 v, int n) {
    for (int i = 0; i < n; ++i) b[at + i] = char(v >> (8 * i));
  };
  Bytes f(0x600, '\0');
  f[0] = 'M';
  f[1] = 'Z';
  put(f, 0x3c, 0x40, 4);
  f.replace(0x40, 4, Bytes("PE\0\0", 4));
  put(f, 0x44, 0x8664, 2);  // machine
  put(f, 0x46, 2, 2);       // sections
  put(f, 0x54, 0xf0, 2);    // optional header size
  put(f, 0x58, 0x20b, 2);   // PE32+
  put(f, 0x58 + 24, base, 8);
  put(f, 0x58 + 32, 0x1000, 4);  // section alignment
  put(f, 0x58 + 36, 0x200, 4);   // file alignment
  struct S {
    u32 vsize, va, rawsize, rawptr, ch;
  };
  S secs[2] = {{0x10, 0x1000, 0x200, 0x200, 0x60000020}, {0x2000, 0x2000, 0x200, 0x400, 0xc0000040}};
  for (int i = 0; i < 2; ++i) {
    size_t s = 0x148 + 40 * i;
    put(f, s + 8, secs[i].vsize, 4);
    put(f, s + 12, secs[i].va, 4);
    put(f, s + 16, secs[i].rawsize, 4);
    put(f, s + 20, secs[i].rawptr, 4);
    put(f, s + 36, secs[i].ch, 4);
  }
  for (size_t k = 0x200; k < 0x600; ++k) f[k] = char(k * 7 + 1);  // code and data, no zeros
  return f;
}

// a PE file on disk: loading lays it out at its virtual addresses, and an image laid out elsewhere (the cache's) reads
// the same tables from its headers
Findings file_layout() {
  namespace fs = std::filesystem;
  fs::path d = fs::temp_directory_path() / ("verifier-pe-" + unique_suffix());
  fs::create_directories(d);
  std::string path = (d / "x.dll").string();
  Bytes file = pe_file(0x180000000);
  std::ofstream(path, std::ios::binary) << file;
  Findings bad;
  Image im = Image::load(path);
  if (im.base != 0x180000000 || im.img.size() != 0x2200 || im.sections.size() != 2 ||
      im.bytes(0x180001000, 1) != file.substr(0x200, 1) || im.bytes(0x180000300, 1) != Bytes(1, '\0'))
    bad.push_back({"layout", "the image is not laid out at its virtual addresses"});
  // the file's bytes in the headers and at each section's start; zeros between them, which are known without reading
  std::vector<std::pair<u64, u64>> parts{{0, 0x200}, {0x1000, 0x1200}, {0x2000, 0x2200}};
  if (im.file_data != parts || im.initialized_size(0x180001100, 0x800) != 0x100 ||
      im.initialized_size(0x180001200, 0xe00) != 0 || im.initialized_size(0x180001f00, 0x200) != 0x200 ||
      im.read(0x180001100, 0x200) != im.bytes(0x180001100, 0x200) || im.read(0x180002100, 0x400).size() != 0x100)
    bad.push_back({"layout", "where the file's data lies"});
  auto buf = std::make_shared<Bytes>(im.img);
  Image same = Image::laid_out(im.headers, *buf, im.file_data, buf);
  if (same.img != im.img || same.sections.size() != 2 || same.base != im.base || same.file_data != im.file_data)
    bad.push_back({"layout", "a copy differs"});
  std::error_code ec;
  fs::remove_all(d, ec);
  return bad;
}

// the exports in any key order, the optional keys left out: functions without a name, library or thunk flag, and
// vtables; the named ones are found by name
Findings neutral_exports() {
  namespace fs = std::filesystem;
  fs::path d = fs::temp_directory_path() / ("verifier-exports-" + unique_suffix());
  fs::create_directories(d);
  Config p;
  p.original = (d / "x.dll").string();
  p.functions = (d / "functions.jsonl").string();
  p.vtables = (d / "vtables.jsonl").string();
  std::ofstream(p.original, std::ios::binary) << pe_file(0x180000000);
  std::ofstream(p.functions, std::ios::binary)
      << "{\"size\": 8, \"ea\": 6442455040}\n"
      << "{\"name\": \"Get\", \"ea\": 6442455048, \"size\": 8}\n"
      << "{\"ea\": 6442455056, \"size\": 4, \"name\": \"Set\", \"thunk\": true}\n";
  std::ofstream(p.vtables, std::ios::binary)
      << "{\"slots\": [6442455048], \"name\": \"??_7Widget@@6B@\", \"vtable_ea\": 6442459136}\n";
  Findings bad;
  {
    Original o(p);
    const IdaFunction* f = o.functions.find(0x180001000);
    if (o.functions.size() != 3 || !f || f->size != 8 || !f->name.empty() || f->lib || f->thunk)
      bad.push_back({"exports", "a function with only its address and size"});
    const u64* get = o.by_name.find("Get");
    if (!get || *get != 0x180001008) bad.push_back({"exports", "a named function in another key order"});
    if (!o.functions.at(0x180001010).thunk) bad.push_back({"exports", "a thunk"});
    if (o.vtables.size() != 1 || o.vtables.at(0x180002000) != std::vector<u64>{0x180001008})
      bad.push_back({"exports", "a vtable in another key order"});
  }
  std::error_code ec;
  fs::remove_all(d, ec);
  return bad;
}

Findings ignored_annotations() {
  namespace fs = std::filesystem;
  fs::path d = fs::temp_directory_path() / ("verifier-ann-" + unique_suffix());
  fs::create_directories(d);
  std::map<std::string, std::string> src{
      {"a.cpp", "// STUB: EXAMPLE 0x180001000\n"},
      {"b.cpp", "// STUB: EXAMPLE 0x180002000\nextern \"C\" void* unk_180002000 = nullptr;\n"},
      {"c.cpp", "// FUNCTION: EXAMPLE 0x180003000\n// a\n// b\n// c\nvoid f(int) {}\n"},
      {"d.cpp", "// FUNCTION: EXAMPLE 0x180004000\nvoid g(int) {}\n// GLOBAL: EXAMPLE 0x180005000\nint h = 1;\n"}};
  for (auto& [n, text] : src) std::ofstream(d / n, std::ios::binary) << text;
  std::vector<Ignored> ignored;
  auto anns = parse_annotations({d.string()}, "EXAMPLE", &ignored);
  std::error_code ec;
  fs::remove_all(d, ec);
  std::vector<std::pair<std::string, int>> got;
  for (auto& i : ignored) got.emplace_back(basename(i.path), i.line);
  std::sort(got.begin(), got.end());
  Findings bad;
  if (got != std::vector<std::pair<std::string, int>>{{"a.cpp", 1}, {"b.cpp", 1}, {"c.cpp", 1}})
    bad.push_back({"ignored", "wrong set"});
  if (anns.size() != 2) bad.push_back({"parsed", std::to_string(anns.size()) + " annotations, want 2"});
  return bad;
}

}  // namespace

void add_inputs_cases(Cases& cases) {
  cases.insert(cases.end(), {
                                {"leaf extent", nullptr, leaf_extent_case},
                                {"decode at two addresses", nullptr, decode_case},
                                {"containing symbol reach", nullptr, containing_reach},
                                {"span stops before a vftable's locator", nullptr, span_before_vftable},
                                {"data items: object ends and padding", nullptr, data_items_load},
                                {"unit: PE file layout", nullptr, file_layout},
                                {"exports in any key order, optional keys left out", nullptr, neutral_exports},
                                {"ignored annotations reported", nullptr, ignored_annotations},
                            });
}

}  // namespace verifier::test
