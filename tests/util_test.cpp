// Small units: hashes, file reading, line splitting, the name table.
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

// unit check: the SHA-256 paths agree (SHA instructions where the CPU has them, portable code), and known digests
Findings sha256_paths() {
  Findings bad;
  if (sha256_hex("abc") != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    bad.push_back({"sha256", "abc"});
  if (sha256_hex("") != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    bad.push_back({"sha256", "empty"});
  Bytes data;
  for (int i = 0; i < 5000; ++i) data.push_back(char((i * 131 + 7) ^ (i >> 3)));
  for (size_t n : {0, 1, 55, 56, 63, 64, 65, 127, 128, 129, 1000, 4096, 5000}) {
    Sha256::force_scalar = true;
    std::string a = sha256_hex(std::string_view(data).substr(0, n));
    Sha256::force_scalar = false;
    std::string b = sha256_hex(std::string_view(data).substr(0, n));
    if (a != b) bad.push_back({"sha256", "length " + std::to_string(n)});
  }
  return bad;
}

Findings content_hashes() {
  Findings bad;
  // XXH64's published values (the 39-byte input runs through the 32-byte stripes)
  const std::pair<const char*, u64> known[] = {{"", 0xEF46DB3751D8E999ull},
                                               {"a", 0xD24EC4F1A98C6E5Bull},
                                               {"abc", 0x44BC2CF5AD770999ull},
                                               {"Nobody inspects the spammish repetition", 0xFBCEA83C8A378BF1ull}};
  for (auto& [text, h] : known)
    if (xxh64(text, 0) != h) bad.push_back({"content hash", std::string("xxh64 of \"") + text + "\""});
  if (content_hash("abc").size() != 32 || content_hash("abc") == content_hash("abd"))
    bad.push_back({"content hash", "abc"});
  return bad;
}

// a file's contents read (below 1 MB) or mapped, each the bytes written; absent files and directories are absent
Findings file_contents() {
  namespace fs = std::filesystem;
  fs::path d = fs::temp_directory_path() / ("verifier-files-" + unique_suffix());
  fs::create_directories(d / "dir");
  Findings bad;
  for (size_t n : {size_t(0), size_t(1), size_t(4097), (size_t(1) << 20) - 1, size_t(1) << 20, (size_t(3) << 20) + 5}) {
    Bytes data(n, '\0');
    for (size_t i = 0; i < n; ++i) data[i] = char(i * 31 + (i >> 11));
    std::string path = (d / ("f" + std::to_string(n))).string();
    std::ofstream(path, std::ios::binary) << data;
    Bytes got;
    bool present = with_contents_if_present(path, [&](std::string_view v) { got = Bytes(v); });
    if (!present || got != data) bad.push_back({"files", "contents of " + std::to_string(n) + " bytes"});
    if (sha256_file_if_present(path) != sha256_hex(data) || sha256_file(path) != sha256_hex(data))
      bad.push_back({"files", "hash of " + std::to_string(n) + " bytes"});
  }
  for (auto& p : {d / "absent", d / "dir"}) {
    bool called = false;
    if (with_contents_if_present(p.string(), [&](std::string_view) { called = true; }) || called ||
        sha256_file_if_present(p.string()) != "")
      bad.push_back({"files", p.filename().string() + " is present"});
    bool threw = false;
    try {
      with_contents(p.string(), [](std::string_view) {});
    } catch (const std::runtime_error&) { threw = true; }
    if (!threw) bad.push_back({"files", "with_contents of " + p.filename().string() + " does not throw"});
  }
  std::error_code ec;
  fs::remove_all(d, ec);
  return bad;
}

// unit check: line splitting (\n, \r\n, \r), in memory and streamed in blocks
// the name table against a std::map, through many growths: a value set again keeps its place
Findings name_table() {
  std::map<std::string, u64> want;
  std::vector<std::string> names;
  for (int i = 0; i < 20000; ++i) names.push_back("?name" + std::to_string(i * 7919 % 20000) + "@@");
  Findings bad;
  // growing from empty, reserved for all, and reserved for too few
  for (size_t reserved : {size_t(0), names.size(), size_t(100)}) {
    NameTable t;
    t.reserve(reserved);
    want.clear();
    for (size_t i = 0; i < names.size(); ++i) {
      t.set(names[i], i);
      want[names[i]] = i;
    }
    for (size_t i = 0; i < names.size(); i += 3) {
      t.set(names[i], i + 1);
      want[names[i]] = i + 1;
    }
    std::string at = " (reserved " + std::to_string(reserved) + ")";
    if (t.size() != want.size()) bad.push_back({"names", "size " + std::to_string(t.size()) + at});
    for (auto& [n, v] : want)
      if (const u64* got = t.find(n); !got || *got != v) {
        bad.push_back({"names", "lookup " + n + at});
        break;
      }
    if (t.find("?absent@@") || t.contains("")) bad.push_back({"names", "found a name never set" + at});
    size_t k = 0;
    for (auto& [n, v] : t)
      if (n != names[k++]) {
        bad.push_back({"names", "order at " + std::to_string(k - 1) + at});
        break;
      }
    // restored from its entries and index (a snapshot): it answers as the table it was taken from
    NameTable r;
    if (!r.restore(std::vector<NameTable::Entry>(t.begin(), t.end()), t.index())) {
      bad.push_back({"names", "a table's own index not restored" + at});
    } else {
      for (auto& [n, v] : want)
        if (const u64* got = r.find(n); !got || *got != v) {
          bad.push_back({"names", "restored lookup " + n + at});
          break;
        }
      if (r.find("?absent@@")) bad.push_back({"names", "a restored table finds a name never set" + at});
    }
  }
  // an index that does not fit its entries is refused
  {
    NameTable t, r;
    for (size_t i = 0; i < 100; ++i) t.set(names[i], i);
    std::vector<NameTable::Entry> e(t.begin(), t.end());
    std::vector<u32> wrong = t.index();
    wrong[0] = u32(e.size() + 1);
    std::vector<u32> few(e.size(), 0);
    if (r.restore(e, wrong) || r.restore(e, few) ||
        r.restore(std::vector<NameTable::Entry>(e.begin(), e.begin() + 50), t.index()))
      bad.push_back({"names", "an index that does not fit restored"});
  }
  // the function table: in order or not, of several at one address the last
  FunctionTable sorted, shuffled;
  std::vector<IdaFunction> in_order, mixed;
  for (u64 i = 0; i < 100; ++i) in_order.push_back({0x1000 + 16 * i, 16, "f", false, false});
  mixed = {in_order[5], in_order[2], in_order[9], in_order[2]};
  mixed.back().size = 99;
  sorted.assign(in_order);
  shuffled.assign(mixed);
  if (sorted.size() != 100 || !sorted.contains(0x1000 + 16 * 99) || sorted.begin()->ea != 0x1000)
    bad.push_back({"functions", "a table in order"});
  if (shuffled.size() != 3 || shuffled.begin()->ea != in_order[2].ea || shuffled.at(in_order[2].ea).size != 99 ||
      (shuffled.begin() + 2)->ea != in_order[9].ea)
    bad.push_back({"functions", "a table out of order, with two at one address"});
  return bad;
}

Findings line_splitting() {
  Findings bad;
  std::string text = "a\nbb\r\nccc\rdddd\n\neee";
  std::vector<std::string> want = {"a", "bb", "ccc", "dddd", "", "eee"}, got;
  for_each_line(text, [&](std::string_view l) { got.emplace_back(l); });
  if (got != want) bad.push_back({"lines", join(got, "|")});
  // streamed: lines across the 1 MB block boundary, a "\r\n" split by it
  namespace fs = std::filesystem;
  fs::path f = fs::temp_directory_path() / ("verifier-lines-" + unique_suffix());
  std::string big;
  std::vector<std::string> want2;
  for (int i = 0; big.size() < (3u << 20); ++i) {
    std::string l(size_t(i * 37 % 1500), char('a' + i % 26));
    want2.push_back(l);
    big += l;
    big += (i % 3 == 0) ? "\r\n" : (i % 3 == 1 ? "\n" : "\r");
  }
  std::ofstream(f, std::ios::binary) << big;
  std::vector<std::string> got2;
  for_each_file_line(f.string(), [&](std::string_view l) { got2.emplace_back(l); });
  std::vector<std::string> got3;
  for_each_line(big, [&](std::string_view l) { got3.emplace_back(l); });
  std::error_code ec;
  fs::remove(f, ec);
  if (got2 != want2 || got3 != want2)
    bad.push_back({"lines", "streamed " + std::to_string(got2.size()) + " vs " + std::to_string(want2.size())});
  return bad;
}

}  // namespace

void add_util_cases(Cases& cases) {
  cases.insert(cases.end(), {
      {"unit: SHA-256 paths agree", nullptr, sha256_paths},
      {"unit: content hash", nullptr, content_hashes},
      {"unit: file contents", nullptr, file_contents},
      {"unit: line splitting", nullptr, line_splitting},
      {"unit: name table", nullptr, name_table},
  });
}

}  // namespace verifier::test
