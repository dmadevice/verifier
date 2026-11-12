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

}  // namespace

void add_cache_cases(Cases& cases) {
  cases.insert(cases.end(), {
      {"name cache file", nullptr, name_cache},
      {"snapshot key", nullptr, snapshot_key},
  });
}

}  // namespace verifier::test
