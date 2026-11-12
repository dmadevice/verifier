// The cache directory: the name cache file and the original's snapshot key.
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

// the sources cache: a file whose size and time are as they were is not read again (here: rewritten with the same size
// and time, its old annotations come back); another time reads it again; a file changed within two seconds is read
// every time and not kept
Findings sources_cache() {
  namespace fs = std::filesystem;
  fs::path d = fs::temp_directory_path() / ("verifier-sources-" + unique_suffix());
  fs::create_directories(d / "src");
  std::string file = (d / "src" / "a.cpp").string(), cache = (d / "sources.bin").string();
  auto write = [&](const char* addr) {
    std::ofstream(file, std::ios::binary)
        << "// FUNCTION: MOD 0x" << addr << "\nvoid Get() {}\n// FUNCTION: MOD 0x99\n";
  };
  auto hour_ago = fs::file_time_type::clock::now() - std::chrono::hours(1);
  auto run = [&](i64 recent) {
    SourceCache c(cache, "key", recent);
    std::vector<Ignored> ign;
    auto anns = parse_annotations({(d / "src").string()}, "MOD", &ign, &c);
    c.save();
    return std::make_pair(anns.size() == 1 ? anns[0].va : 0, ign.size());
  };
  Findings bad;
  write("10");
  fs::last_write_time(file, hour_ago);
  if (run(two_seconds_ago()) != std::make_pair(u64(0x10), size_t(1))) bad.push_back({"sources", "first read"});
  write("20");  // same size
  fs::last_write_time(file, hour_ago);
  if (run(two_seconds_ago()).first != 0x10) bad.push_back({"sources", "an unchanged stamp read again"});
  fs::last_write_time(file, hour_ago + std::chrono::seconds(1));
  if (run(two_seconds_ago()).first != 0x20) bad.push_back({"sources", "a new time not read again"});
  // the run started before the file's time: read, and not kept for the next run
  write("30");
  fs::last_write_time(file, hour_ago);
  i64 before = i64(hour_ago.time_since_epoch().count()) - 1;
  if (run(before).first != 0x30) bad.push_back({"sources", "a recent file not read"});
  write("40");
  fs::last_write_time(file, hour_ago);
  if (run(two_seconds_ago()).first != 0x40) bad.push_back({"sources", "a recent file kept"});
  {
    SourceCache other(cache, "another key", two_seconds_ago());
    if (other.find(ListedFile{file, fs::file_size(file), i64(hour_ago.time_since_epoch().count())}))
      bad.push_back({"sources", "another key's entries used"});
  }
  std::error_code ec;
  fs::remove_all(d, ec);
  return bad;
}

// the original's snapshot key: none while an input is younger than two seconds (the snapshot is neither used nor
// written), and the configured hash part of it
Findings snapshot_key() {
  namespace fs = std::filesystem;
  fs::path d = fs::temp_directory_path() / ("verifier-test-" + unique_suffix());
  fs::create_directories(d);
  Findings bad;
  auto write = [](const std::string& path, const std::string& text) { std::ofstream(path, std::ios::binary) << text; };
  Config p;
  p.original = (d / "orig.dll").string();
  write(p.original, "1");
  p.cache_dir = (d / "cache").string();
  if (!Original::snapshot_key(p).empty())
    bad.push_back({"snapshot", "the snapshot's key trusts an input written just now"});
  for (auto* f : p.snapshot_inputs())
    if (!f->empty() && fs::exists(*f))
      fs::last_write_time(*f, fs::file_time_type::clock::now() - std::chrono::hours(1));
  std::string key = Original::snapshot_key(p);
  if (key.empty()) bad.push_back({"snapshot", "no snapshot key for inputs an hour old"});
  if (Original::snapshot_key(p) != key) bad.push_back({"snapshot", "the key of the same inputs differs"});
  p.original_sha256 = "ab";
  Config q = p;
  q.original_sha256 = "cd";
  if (Original::snapshot_key(p) == key || Original::snapshot_key(p) == Original::snapshot_key(q))
    bad.push_back({"snapshot", "the snapshot's key ignores the configured hash"});
  std::string before = Original::snapshot_key(p);
  write(p.original, "22");
  fs::last_write_time(p.original, fs::file_time_type::clock::now() - std::chrono::hours(1));
  if (Original::snapshot_key(p) == before) bad.push_back({"snapshot", "the snapshot's key ignores the original"});
  std::error_code ec;
  fs::remove_all(d, ec);
  return bad;
}

// the name cache file: what a run stores is what the next run reads (in the order of its map, new names added,
// ids equal exactly when the strings are), and a damaged file is ignored. Names without a leading '?' need no
// undname.
Findings name_cache() {
  namespace fs = std::filesystem;
  fs::path d = fs::temp_directory_path() / ("verifier-names-" + unique_suffix());
  fs::create_directories(d);
  std::string file = (d / "names.bin").string();
  auto infos_of = [](NameCache& nc, const std::vector<std::string_view>& names) {
    std::vector<std::string> out;
    for (auto& ids : nc.load(names)) {
      NameInfo ni = nc.info(ids);
      out.push_back(std::string(ni.decorated) + "|" + std::string(ni.qualified) + "|" + std::string(ni.signature) +
                    "|" + std::string(ni.owner) + "|" + std::string(nc.text(ids.last1)) + "|" +
                    std::string(nc.text(ids.last2)));
    }
    return out;
  };
  Findings bad;
  std::vector<std::string_view> first = {"N::A::f", "N::B::f", "g", "N::A::f", "M::N::A::f"};
  std::vector<std::string_view> second = {"h", "N::B::f", "M::N::A::f", "N::A::f", "N::C::f"};
  std::vector<std::string> want1, want2;
  {
    NameCache nc(file, "key", "");
    want1 = infos_of(nc, first);
    nc.save();
  }
  {
    NameCache nc(file, "key", "");
    if (infos_of(nc, first) != want1) bad.push_back({"names", "reloaded entries differ"});
    auto infos = nc.load(second);
    want2 = infos_of(nc, second);
    nc.save();
    // the same qualified name, the same id; f is every name's last component
    if (infos[1].last1 != infos[3].last1 || infos[1].qualified == infos[3].qualified ||
        nc.text(infos[1].qualified) != nc.info(infos[1]).qualified)
      bad.push_back({"names", "ids"});
    if (!nc.id_of("f") || nc.id_of("no such string")) bad.push_back({"names", "id_of"});
  }
  {
    NameCache nc(file, "key", "");
    if (infos_of(nc, second) != want2) bad.push_back({"names", "entries after adding names differ"});
  }
  {
    NameCache nc(file, "other key", "");  // another undname: the file is not used
    if (nc.string_count() != 0) bad.push_back({"names", "file of another key read"});
  }
  {
    // a run replaces the file while another has it mapped: the other goes on reading the old one
    NameCache reader(file, "key", "");
    NameCache writer(file, "key", "");
    writer.load({"i"});
    writer.save();
    if (infos_of(reader, second) != want2) bad.push_back({"names", "the mapped file changed"});
  }
  {
    NameCache nc(file, "key", "");
    if (!nc.id_of("i")) bad.push_back({"names", "not replaced while mapped"});
    nc.load(second);
    nc.save();
  }
  {
    // the names of other builds are kept after this build's, the most recent first, as many as this build has
    NameCache a(file, "key", "");
    a.load({"p", "q", "r"});
    a.save();
    NameCache b(file, "key", "");
    b.load({"s", "t"});
    if (b.has_new() != true || !b.id_of("p")) bad.push_back({"names", "has_new, or the old file read"});
    b.save();
    NameCache c(file, "key", "");
    c.load({"s", "t"});
    if (c.has_new() || !c.id_of("p") || !c.id_of("q") || c.id_of("r"))
      bad.push_back({"names", "other builds' names kept: not p, q only"});
    auto before = fs::last_write_time(file);
    c.save();  // starts with s, t and keeps two others: nothing to write
    if (fs::last_write_time(file) != before) bad.push_back({"names", "rewritten with nothing new"});
    NameCache e(file, "key", "");
    e.load({"p"});  // in the file, not first: a save puts it first
    if (e.has_new()) bad.push_back({"names", "a name of another build undecorated again"});
    e.save();
    NameCache f2(file, "key", "");
    f2.load({"p"});
    if (!f2.id_of("s") || f2.id_of("t")) bad.push_back({"names", "after reordering: not p then s"});
  }
  {
    NameCache nc(file, "key", "");
    nc.load(second);
    nc.save();
  }
  fs::resize_file(file, fs::file_size(file) - 3);
  {
    NameCache nc(file, "key", "");
    if (nc.string_count() != 0) bad.push_back({"names", "truncated file read"});
    if (infos_of(nc, second) != want2) bad.push_back({"names", "entries without the file differ"});
  }
  std::error_code ec;
  fs::remove_all(d, ec);
  return bad;
}

// what a decoded function holds, as text (a stored one must give the same)
std::string code_text(const Code& c) {
  std::string s = std::to_string(c.code.size()) + " " + std::to_string(c.cut) + " " +
                  std::to_string(c.resume.value_or(-1)) + " " + std::to_string(c.complete) + " " +
                  std::to_string(c.shape.known) + std::to_string(c.shape.ends_in_jump) + " " +
                  std::to_string(c.shape.reach) + ";";
  for (auto& [t, size] : c.tables) s += " t" + std::to_string(t) + ":" + std::to_string(size);
  for (i64 d : c.shape.indexed) s += " i" + std::to_string(d);
  for (auto& l : c.insns) {
    s += "; " + std::to_string(l.off) + " " + std::to_string(l.size) + " " + std::to_string(l.addressed) + " " +
         c.mnemonic(l).str() + " (" + c.insn(l).text() + ")";
    for (auto& f : c.fields(l))
      s += " " + std::to_string(f.kind) + "@" + std::to_string(f.off) + "/" + std::to_string(f.size) + "=" +
           hex_signed(f.value) + "," + std::to_string(f.access) + "," + std::to_string(f.indexed);
  }
  return s;
}

// the original's decoded functions kept between runs: each fixture case's function read back as decoded; another key,
// or a damaged file, gives nothing back
Findings code_store() {
  namespace fs = std::filesystem;
  fs::path d = fs::temp_directory_path() / ("verifier-code-" + unique_suffix());
  std::string file = (d / "code.bin").string();
  Findings bad;
  size_t kept = 0;
  for (auto& c : fixtures()["cases"].arr) {
    Image img = fixture_image(c["orig"]);
    u64 start = u64(c["ofn"].arr[0].as_int()), end = u64(c["ofn"].arr[1].as_int());
    std::string name = c["name"].as_str();
    std::string decoded = code_text(Code(img, start, end));
    std::error_code ec;
    fs::remove(file, ec);  // the cases' images differ at the same addresses: one store each
    {
      CodeStore store(file, "key");
      CodeCache cache(&img, &store);
      cache.code(start, end);
      store.save();
    }
    CodeStore store(file, "key");
    auto back = store.find(img, start, end);
    if (!back || code_text(*back) != decoded) bad.push_back({"code", name + ": not as decoded"});
    kept += back != nullptr;
    if (CodeStore(file, "other key").find(img, start, end)) bad.push_back({"code", name + ": another key's used"});
  }
  if (!kept) bad.push_back({"code", "nothing kept"});
  // cut short: not used at all
  std::string data = read_file(file);
  std::ofstream(file, std::ios::binary | std::ios::trunc) << data.substr(0, data.size() - 3);
  Image img = fixture_image(fixtures()["cases"].arr.back()["orig"]);
  auto& last = fixtures()["cases"].arr.back()["ofn"].arr;
  if (CodeStore(file, "key").find(img, u64(last[0].as_int()), u64(last[1].as_int())))
    bad.push_back({"code", "a damaged file used"});
  std::error_code ec;
  fs::remove_all(d, ec);
  return bad;
}

}  // namespace

void add_cache_cases(Cases& cases) {
  cases.insert(cases.end(), {
                                {"name cache file", nullptr, name_cache},
                                {"snapshot key", nullptr, snapshot_key},
                                {"sources cache", nullptr, sources_cache},
                                {"original code store", nullptr, code_store},
                            });
}

}  // namespace verifier::test
