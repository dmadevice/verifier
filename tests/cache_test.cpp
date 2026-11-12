// The cache directory and the replay record: name cache, code, diff and sources stores, keys.
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

Problems replay_key() {
  namespace fs = std::filesystem;
  fs::path d = fs::temp_directory_path() / ("verifier-test-" + unique_suffix());
  fs::create_directories(d / "src");
  Problems bad;
  std::map<std::string, std::string> files{{"x.dll", (d / "x.dll").string()},
                                           {"x.map", (d / "x.map").string()},
                                           {"matched.txt", (d / "matched.txt").string()},
                                           {"src/a.cpp", (d / "src" / "a.cpp").string()}};
  Args a;
  a.rebuilt = files["x.dll"];
  a.map = files["x.map"];
  a.matched = files["matched.txt"];
  a.src = {(d / "src").string()};
  Config p;
  std::vector<std::string> args;
  auto write = [](const std::string& path, const std::string& text) { std::ofstream(path, std::ios::binary) << text; };
  std::vector<std::pair<std::string, std::function<void()>>> changes;
  for (auto& [n, path] : files) changes.emplace_back(n, [&write, path = path] { write(path, "2"); });
  changes.emplace_back("added source", [&] { write((d / "src" / "b.h").string(), ""); });
  for (auto& [name, change] : changes) {
    for (auto& [n, path] : files) write(path, "1");
    args = {"--check"};
    std::error_code ec;
    fs::remove(d / "src" / "b.h", ec);
    std::string key = run_key(a, p, "verifier");
    if (run_key(a, p, "verifier") != key) bad.push_back({"replay", "the key of the same inputs differs"});
    change();
    if (run_key(a, p, "verifier") == key) bad.push_back({"replay", "the key ignores " + name});
  }
  if (run_key(a, p, "verifier") == run_key(a, p, "another verifier"))
    bad.push_back({"replay", "the key ignores the verifier"});
  std::error_code removed;
  fs::remove(d / "src" / "b.h", removed);  // the last change's
  // the command: its arguments, the root and the configuration's contents
  p.file = (d / "verifier.conf").string();
  write(p.file, "a = 1");
  std::string command = command_key(args, p);
  if (command_key(args, p) != command) bad.push_back({"replay", "the command of the same run differs"});
  if (command_key({"--check", "--json"}, p) == command) bad.push_back({"replay", "the command ignores the arguments"});
  Config q = p;
  q.root = "elsewhere";
  if (command_key(args, q) == command) bad.push_back({"replay", "the command ignores the root"});
  write(p.file, "a = 2");
  if (command_key(args, p) == command) bad.push_back({"replay", "the command ignores the configuration's contents"});
  // a run that computes the key at its end takes the sources from parsing them: the same key, the files that cannot
  // hold an annotation included
  fs::create_directories(d / "src" / "sub");
  write((d / "src" / "notes.txt").string(), "x");
  write((d / "src" / "sub" / "c.cpp").string(), "// FUNCTION: EXAMPLE 0x10\nvoid f() {}\n");
  std::vector<std::string> seen;
  std::map<std::string, std::string> hashes;
  std::vector<ListedFile> listed;
  parse_annotations(a.src, "EXAMPLE", nullptr, [&](const ListedFile& f, std::string_view data) {
    seen.push_back(f.path);
    listed.push_back(f);
    hashes[f.path] = content_hash(data);
  });
  auto hash = [&](const std::string& f) {
    auto it = hashes.find(f);
    return it != hashes.end() ? it->second : fs::exists(f) ? content_hash_file_if_present(f) : std::string();
  };
  if (seen.size() != 3 || run_key(a, p, "verifier", seen, hash) != run_key(a, p, "verifier"))
    bad.push_back({"replay", "the key from parsing the sources differs from the walked one"});
  // and the stamps from that listing are the listed ones (an hour old here: none are recent)
  auto hour_ago = fs::file_time_type::clock::now() - std::chrono::hours(1);
  for (auto& f : listed) fs::last_write_time(f.path, hour_ago);
  for (auto* f : {&a.rebuilt, &a.map}) fs::last_write_time(*f, hour_ago);
  fs::last_write_time(*a.matched, hour_ago);
  listed.clear();
  parse_annotations(a.src, "EXAMPLE", nullptr, [&](const ListedFile& f, std::string_view) { listed.push_back(f); });
  std::string stamps = stamp_key(a, p, "");
  if (stamps.empty() || stamp_key(a, p, "", listed, two_seconds_ago()) != stamps)
    bad.push_back({"replay", "the stamps from parsing the sources differ from the listed ones"});
  // the original: by its contents without a cache, by the snapshot's key (size, time, configured hash) with one
  p.original = (d / "orig.dll").string();
  write(p.original, "1");
  std::string plain = run_key(a, p, "verifier");
  write(p.original, "2");
  if (run_key(a, p, "verifier") == plain) bad.push_back({"replay", "the key ignores the original's contents"});
  p.cache_dir = (d / "cache").string();
  std::string cached = run_key(a, p, "verifier");
  if (cached == plain) bad.push_back({"replay", "the key with a cache is the one without"});
  write(p.original, "22");
  if (run_key(a, p, "verifier") == cached) bad.push_back({"replay", "the key with a cache ignores the original"});
  // inputs changed within two seconds: no snapshot key (the snapshot is neither used nor written)
  if (!Original::snapshot_key(p).empty())
    bad.push_back({"replay", "the snapshot's key trusts an input written just now"});
  for (auto* f : p.snapshot_inputs())
    if (!f->empty() && fs::exists(*f))
      fs::last_write_time(*f, fs::file_time_type::clock::now() - std::chrono::hours(1));
  if (Original::snapshot_key(p).empty()) bad.push_back({"replay", "no snapshot key for inputs an hour old"});
  cached = run_key(a, p, "verifier");
  p.original_sha256 = "ab";
  if (run_key(a, p, "verifier") == cached || Original::snapshot_key(p) == [&] {
        Config q = p;
        q.original_sha256 = "cd";
        return Original::snapshot_key(q);
      }())
    bad.push_back({"replay", "the snapshot's key ignores the configured hash"});
  std::error_code ec;
  fs::remove_all(d, ec);
  return bad;
}

// the name cache file: what a run stores is what the next run reads (in the order of its map, new names added,
// ids equal exactly when the strings are), and a damaged file is ignored. Names without a leading '?' need no
// undname.
Problems name_cache() {
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
  Problems bad;
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

// -- the cache directory's stores ---------------------------------------------------------------------------

// a decoded function's every part, as the comparison reads it
bool same_code(const Code& a, const Code& b, std::string& why) {
  auto fail = [&](const char* w) {
    why = w;
    return false;
  };
  if (a.start != b.start || a.end != b.end || a.code != b.code) return fail("range or bytes");
  if (a.relocated != b.relocated || a.complete != b.complete || a.cut != b.cut || a.resume != b.resume)
    return fail("flags");
  if (a.tables != b.tables) return fail("tables");
  if (a.insns.size() != b.insns.size() || a.field_list.size() != b.field_list.size()) return fail("counts");
  for (size_t i = 0; i < a.insns.size(); ++i) {
    const Lean &x = a.insns[i], &y = b.insns[i];
    if (x.off != y.off || x.field != y.field || x.size != y.size || x.nfields != y.nfields ||
        x.addressed != y.addressed || a.mnemonic(x).str() != b.mnemonic(y).str())
      return fail("instruction");
  }
  for (size_t i = 0; i < a.field_list.size(); ++i) {
    const Field &x = a.field_list[i], &y = b.field_list[i];
    if (x.value != y.value || x.access != y.access || x.off != y.off || x.size != y.size || x.kind != y.kind)
      return fail("field");
  }
  return true;
}

// a function with every kind of field: a call out of it, a RIP-relative load, a relocated 64-bit immediate, and an
// in-function switch table (mov eax, [rcx*4 + table]) that ends its code; then `n` small functions after it
struct StoreImage {
  Side s{0};
  u64 f = 0, f_end = 0, imm = 0;  // imm: where the relocated 64-bit immediate is
  std::vector<std::pair<u64, u64>> small;
  explicit StoreImage(int n) {
    u64 g = s.put(DATA, le32b(7));
    u64 callee = s.put(TEXT, unhex("c3"));
    f = BASE + ((s.cur[TEXT] + 15) & ~u64(15));
    Bytes code = call(f, callee) + mov_eax_g(f + 5, g) + mov_eax_g(f + 11, g);  // an odd number of fields
    u64 imm_at = f + code.size() + 2;
    code += unhex("48b8") + le64b(g);            // mov rax, g (relocated)
    u64 table_rva = f - BASE + code.size() + 8;  // after the mov eax, [rcx*4 + table] and the ret
    code += unhex("8b048d") + le32b(u32(table_rva)) + unhex("c3");
    code += le32b(1) + le32b(2) + le32b(3);  // the table
    s.put(TEXT, code);
    s.relocs.push_back(imm_at);
    imm = imm_at;
    f_end = f + code.size();
    for (int i = 0; i < n; ++i) {
      u64 at = s.put(TEXT, unhex("b8") + le32b(u32(i)) + unhex("c3"));
      small.push_back({at, at + 6});
    }
  }
};

// the code store of StoreImage(22), written by this process with other mnemonics interned first (another run numbers
// them otherwise: the store names them by text)
int write_other_code_store(const std::string& path) {
  for (const char* m : {"zz-first", "zz-second", "zz-third"}) Mnem{m};
  StoreImage si(22);
  Image img = si.s.image();
  CodeStore st(path, img, "decoder 1");
  for (auto& [a, b] : si.small) st.code(a, b);
  st.code(si.f, si.f_end);
  st.save();
  return 0;
}

Problems code_store_case() {
  namespace fs = std::filesystem;
  Problems bad;
  fs::path d = fs::temp_directory_path() / ("verifier-code-" + unique_suffix());
  fs::create_directories(d);
  std::string path = (d / "code.bin").string();
  StoreImage si(22);
  Image img = si.s.image();
  auto check = [&](CodeStore& st, const Image& im, u64 a, u64 b, const char* what) {
    auto got = st.code(a, b);
    Code fresh(im, a, b);
    std::string why;
    if (!same_code(*got, fresh, why)) bad.push_back({"code store", std::string(what) + ": " + why});
  };
  {
    CodeStore st(path, img, "decoder 1");
    check(st, img, si.f, si.f_end, "decoded");
    for (auto& [a, b] : si.small) check(st, img, a, b, "decoded");
    if (st.stats().hits || st.stats().misses != 23) bad.push_back({"code store", "an empty store has hits"});
    st.save();
  }
  {
    CodeStore st(path, img, "decoder 1");
    check(st, img, si.f, si.f_end, "from the store");
    for (auto& [a, b] : si.small) check(st, img, a, b, "from the store");
    if (st.stats().hits != 23 || st.stats().misses)
      bad.push_back({"code store", "a stored function was decoded again"});
    Code fresh(img, si.f, si.f_end);
    if (fresh.field_list.size() < 4 || fresh.tables.empty())
      bad.push_back({"code store", "the test function lacks a field kind"});
    if (fresh.field_list.size() % 2 ==
        0)  // its fields end between 8-byte boundaries: the entries after it must still be read
      bad.push_back({"code store", "the test function has an even number of fields"});
  }
  {
    // written by another process, whose mnemonic ids differ from this one's
    std::string other = (d / "other.bin").string();
    std::string cmd = "\"" + self_path + "\" --write-code-store \"" + other + "\"";
#ifdef _WIN32
    cmd = "\"" + cmd + "\"";  // cmd /c drops the outer quotes of a line holding more than two
#endif
    if (std::system(cmd.c_str()) != 0 || !fs::exists(other)) {
      bad.push_back({"code store", "the second process wrote nothing"});
    } else {
      CodeStore st(other, img, "decoder 1");
      check(st, img, si.f, si.f_end, "from another process");
      for (auto& [a, b] : si.small) check(st, img, a, b, "from another process");
      if (st.stats().hits != 23) bad.push_back({"code store", "another process's functions not used"});
    }
  }
  {
    Side changed = si.s;
    changed.write(si.f + 7, le32b(0x40));  // the RIP-relative displacement
    Image img2 = changed.image();
    CodeStore st(path, img2, "decoder 1");
    check(st, img2, si.f, si.f_end, "bytes changed");
    if (st.stats().misses != 1) bad.push_back({"code store", "changed bytes taken from the store"});
    check(st, img2, si.small[0].first, si.small[0].second, "unchanged neighbour");
    if (st.stats().hits != 1) bad.push_back({"code store", "an unchanged function was not taken from the store"});
  }
  {
    Side changed = si.s;
    changed.relocs.clear();
    Image img2 = changed.image();
    CodeStore st(path, img2, "decoder 1");
    check(st, img2, si.f, si.f_end, "relocation gone");
    if (st.stats().misses != 1) bad.push_back({"code store", "changed relocations taken from the store"});
  }
  {
    CodeStore st(path, img, "decoder 2");
    check(st, img, si.f, si.f_end, "other decoder");
    if (st.stats().misses != 1) bad.push_back({"code store", "another decoder's functions used"});
  }
  {
    CodeStore st(path, img, "decoder 1");
    auto [a, b] = si.small[0];
    check(st, img, a + 1, b, "other range");  // the same bytes from another start: not the stored function
    if (st.stats().misses != 1) bad.push_back({"code store", "a function used for another range"});
  }
  // a run asking for every stored function and one it lacks decodes that one without rewriting the file; one that lacks
  // a twentieth of what it asks for rewrites it, and the next run finds them all
  std::string before = read_file(path);
  u64 extra = si.s.put(TEXT, unhex("b863000000c3"));
  Side more = si.s;
  Image img3 = more.image();
  {
    CodeStore st(path, img3, "decoder 1");
    check(st, img3, si.f, si.f_end, "stored");
    for (auto& [a, b] : si.small) check(st, img3, a, b, "stored");
    check(st, img3, extra, extra + 6, "new");
    st.save();
  }
  if (read_file(path) != before) bad.push_back({"code store", "rewritten for one missing function in 24"});
  {
    CodeStore st(path, img3, "decoder 1");
    check(st, img3, extra, extra + 6, "new");
    for (int i = 0; i < 2; ++i) check(st, img3, si.small[size_t(i)].first + 1, si.small[size_t(i)].second, "new");
    st.save();
  }
  {
    CodeStore st(path, img3, "decoder 1");
    check(st, img3, extra, extra + 6, "kept");
    check(st, img3, si.f, si.f_end, "kept");
    if (st.stats().hits != 2 || st.stats().misses) bad.push_back({"code store", "a rewrite lost functions"});
  }
  fs::remove_all(d);
  return bad;
}

Problems diff_store_case() {
  namespace fs = std::filesystem;
  Problems bad;
  fs::path d = fs::temp_directory_path() / ("verifier-diffs-" + unique_suffix());
  fs::create_directories(d);
  std::string path = (d / "diffs.bin").string();
  StoreImage o(0);
  Side changed = o.s;
  changed.write(o.imm, le64b(0x180009999));  // the 64-bit immediate: another value
  Side retargeted = o.s;
  retargeted.write(o.f + 1, le32b(u32(i32(0x40))));  // the call: the same instructions and offsets, another callee
  Side reordered = o.s;
  reordered.write(o.f + 5, unhex("90909090909090909090909090909090"));
  Image io = o.s.image(), ir = changed.image(), ir2 = reordered.image(), ir3 = retargeted.image();
  auto by_va = [](u64 t) { return Key::of_va(t); };
  auto toks = [&](const Image& im) { return symbolise(Code(im, o.f, o.f_end), by_va, false); };
  auto offs = [&](const Image& im) {
    std::vector<u32> v;
    Code c(im, o.f, o.f_end);
    for (auto& l : c.insns) v.push_back(l.off);
    return v;
  };
  NameOf names = [&](u64 va) { return va == o.f ? std::string_view("f") : std::string_view(); };
  Toks ot = toks(io), rt = toks(ir), rt2 = toks(ir2), rt3 = toks(ir3);
  auto want = [&](const Toks& r, const Image& im) {
    return DiffStore::Entry{classify(ot, r), insn_diff(offs(io), offs(im), ot, r, names)};
  };
  auto same = [](const DiffStore::Entry& a, const DiffStore::Entry& b) {
    return a.category == b.category && a.diff == b.diff;
  };
  {
    DiffStore st(path, "key 1");
    if (!same(st.get(offs(io), offs(ir), ot, rt, names), want(rt, ir))) bad.push_back({"diff store", "made"});
    if (st.stats().misses != 1) bad.push_back({"diff store", "an empty store has hits"});
    st.save();
  }
  {
    DiffStore st(path, "key 1");
    if (!same(st.get(offs(io), offs(ir), ot, rt, names), want(rt, ir))) bad.push_back({"diff store", "from the store"});
    if (st.stats().hits != 1) bad.push_back({"diff store", "a stored diff was made again"});
    if (!same(st.get(offs(io), offs(ir2), ot, rt2, names), want(rt2, ir2)))
      bad.push_back({"diff store", "other tokens"});
    if (st.stats().misses != 1) bad.push_back({"diff store", "other tokens taken from the store"});
    if (offs(ir3) != offs(io) || !same(st.get(offs(io), offs(ir3), ot, rt3, names), want(rt3, ir3)))
      bad.push_back({"diff store", "other targets at the same offsets"});
    // the unchanged function against itself differs from each stored case in one field only: the immediate's value
    // (changed) or the call's target (retargeted); a key leaving either out would find that case's diff
    if (!same(st.get(offs(io), offs(io), ot, ot, names), want(ot, io)))
      bad.push_back({"diff store", "one field apart"});
    // the same tokens but for the name the call's target resolves to
    auto named = [&](const char* n) {
      Toks t = ot;
      t[0].ops[0].key = Key::named(Key::UNRESOLVED, n);
      return t;
    };
    Toks na = named("alpha"), nb = named("beta");
    st.get(offs(io), offs(io), ot, na, names);
    if (!same(st.get(offs(io), offs(io), ot, nb, names),
              DiffStore::Entry{classify(ot, nb), insn_diff(offs(io), offs(io), ot, nb, names)}))
      bad.push_back({"diff store", "another name"});
    st.save();
  }
  {
    DiffStore st(path, "key 2");
    st.get(offs(io), offs(ir), ot, rt, names);
    if (st.stats().misses != 1) bad.push_back({"diff store", "another key's diffs used"});
  }
  {
    DiffStore st(path, "key 1");
    st.get(offs(io), offs(ir), ot, rt, names);
    st.get(offs(io), offs(ir2), ot, rt2, names);
    if (st.stats().hits != 2) bad.push_back({"diff store", "a rewrite lost diffs"});
  }
  fs::remove_all(d);
  return bad;
}

Problems source_cache_case() {
  namespace fs = std::filesystem;
  Problems bad;
  fs::path d = fs::temp_directory_path() / ("verifier-sources-" + unique_suffix());
  fs::create_directories(d / "src");
  std::string cache = (d / "sources.bin").string(), root = (d / "src").string();
  auto write = [&](const std::string& name, const std::string& text, int age_s) {
    fs::path f = d / "src" / name;
    std::ofstream(f, std::ios::binary) << text;
    fs::last_write_time(f, fs::file_time_type::clock::now() - std::chrono::seconds(age_s));
  };
  write("a.cpp", "// FUNCTION: MOD 0x1000\nint f(int x) { return x; }\n// GLOBAL: MOD 0x2000\n\n", 3600);
  write("b.h", "// VTABLE: MOD 0x3000 FOLDED\nclass C {\n// STUB: MOD 0x4000 (int)\nvoid g(int);\n", 3600);
  write("notes.txt", "no annotations\n", 3600);
  struct Run {
    std::vector<Annotation> anns;
    std::vector<Ignored> ign;
    std::map<std::string, std::string> hashes;
  };
  auto same = [](const Run& a, const Run& b) {
    if (a.anns.size() != b.anns.size() || a.ign.size() != b.ign.size() || a.hashes != b.hashes) return false;
    for (size_t i = 0; i < a.anns.size(); ++i) {
      const Annotation &x = a.anns[i], &y = b.anns[i];
      if (x.kind != y.kind || x.va != y.va || x.name != y.name || x.flags.folded != y.flags.folded ||
          x.flags.dtor != y.flags.dtor || x.flags.sig != y.flags.sig || x.path != y.path || x.line != y.line)
        return false;
    }
    for (size_t i = 0; i < a.ign.size(); ++i)
      if (a.ign[i].path != b.ign[i].path || a.ign[i].line != b.ign[i].line || a.ign[i].text != b.ign[i].text)
        return false;
    return true;
  };
  auto uncached = [&] {
    Run r;
    r.anns = parse_annotations({root}, "MOD", &r.ign, [&](const ListedFile& f, std::string_view data) {
      r.hashes[f.path] = content_hash(data);
    });
    return r;
  };
  auto cached = [&](const std::string& key, SourceCache::Stats& stats) {
    Run r;
    SourceCache c(cache, key, two_seconds_ago());
    r.anns = parse_annotations({root}, "MOD", &r.ign, nullptr, &c,
                               [&](const ListedFile& f, const std::string& h) { r.hashes[f.path] = h; });
    c.save();
    stats = c.stats();
    return r;
  };
  SourceCache::Stats st;
  if (!same(cached("key", st), uncached()) || st.hits) bad.push_back({"sources cache", "first run"});
  if (!same(cached("key", st), uncached()) || st.hits != 3 || st.misses)
    bad.push_back({"sources cache", "unchanged files read again"});
  write("a.cpp",
        "// FUNCTION: MOD 0x1000\nint f(int x) { return x; }\n// FUNCTION: MOD 0x1100\nint h() { return 1; }\n", 1800);
  if (!same(cached("key", st), uncached()) || st.hits != 2 || st.misses != 1)
    bad.push_back({"sources cache", "an edited file"});
  // an edit within one tick of the file clock leaves the size and time as they were: a file that recent is read again
  write("b.h", "// VTABLE: MOD 0x3000 FOLDED\nclass C {\n// STUB: MOD 0x4000 (int)\nvoid g(int);\n", 0);
  auto t = fs::last_write_time(d / "src" / "b.h");
  cached("key", st);
  write("b.h", "// VTABLE: MOD 0x3008 FOLDED\nclass C {\n// STUB: MOD 0x4008 (int)\nvoid g(int);\n", 0);
  fs::last_write_time(d / "src" / "b.h", t);
  if (!same(cached("key", st), uncached()) || st.misses != 1)
    bad.push_back({"sources cache", "a file written within two seconds"});
  if (!same(cached("other key", st), uncached()) || st.hits)
    bad.push_back({"sources cache", "another key's entries used"});
  fs::remove_all(d);
  return bad;
}

Problems replay_record() {
  namespace fs = std::filesystem;
  Problems bad;
  fs::path d = fs::temp_directory_path() / ("verifier-last-" + unique_suffix());
  fs::create_directories(d);
  std::string path = (d / "last.txt").string();
  std::string stamps(300, 's'), out = "MATCH 0x1000\n", report = content_hash("{\n  \"results\": []\n}\n");
  auto never = [] { return std::string("not asked for"); };
  bool asked = false;
  auto is = [&](std::string v) {
    return [&asked, v] {
      asked = true;
      return v;
    };
  };
  save_last(path, "command", "image stamp", stamps, "image hash", "key", out, report, 1);
  Last l;
  // the stamps as given: a run with the same ones replays by them, without hashing the image or the inputs
  if (!load_last(
          path, "command", "image stamp", [&] { return stamps; }, is("other"), is("other"), l) ||
      !l.by_stamps || asked)
    bad.push_back({"replay", "the same stamps do not replay by themselves"});
  if (l.out != out || l.report_hash != report || l.rc != 1)
    bad.push_back({"replay", "the output, report hash or status differs"});
  // other stamps: the image's hash and the key decide
  asked = false;
  if (!load_last(
          path, "command", "image stamp", [] { return std::string("other stamps"); }, is("image hash"), is("key"), l) ||
      l.by_stamps || !asked)
    bad.push_back({"replay", "stale stamps with the same contents do not replay by the contents"});
  if (load_last(
          path, "command", "image stamp", [] { return std::string("other stamps"); }, is("other image"), never, l))
    bad.push_back({"replay", "another image replays"});
  if (load_last(path, "another command", "image stamp", [&] { return stamps; }, never, never, l))
    bad.push_back({"replay", "another command replays"});
  // no stamps (an input changed within two seconds): only the contents decide
  save_last(path, "command", "image stamp", "", "image hash", "key", out, "", 0);
  if (!load_last(
          path, "command", "image stamp", [] { return std::string(); }, is("image hash"), is("key"), l) ||
      l.by_stamps)
    bad.push_back({"replay", "a record without stamps does not replay by the contents"});
  if (!l.report_hash.empty()) bad.push_back({"replay", "a run without a report recorded one"});
  fs::remove_all(d);
  return bad;
}

Problems stamp_keys() {
  namespace fs = std::filesystem;
  fs::path d = fs::temp_directory_path() / ("verifier-stamps-" + unique_suffix());
  fs::create_directories(d / "src" / "sub");
  Problems bad;
  auto write = [](const fs::path& path, const std::string& text) { std::ofstream(path, std::ios::binary) << text; };
  auto old = fs::file_time_type::clock::now() - std::chrono::hours(1);
  std::vector<fs::path> files{
      d / "x.dll", d / "x.map", d / "matched.txt", d / "src" / "a.cpp", d / "src" / "sub" / "b.h", d / "verifier.exe"};
  for (auto& f : files) {
    write(f, "1");
    fs::last_write_time(f, old);
  }
  write(d / "verifier.conf", "a = 1");
  Args a;
  a.rebuilt = files[0].string();
  a.map = files[1].string();
  a.matched = files[2].string();
  a.src = {(d / "src").string()};
  Config p;
  p.file = (d / "verifier.conf").string();  // by its contents: young or not
  std::vector<std::string> args{"--check"};
  std::string exe = files[5].string();
  std::string key = stamp_key(a, p, exe);
  if (key.empty() || stamp_key(a, p, exe) != key) bad.push_back({"stamps", "no key, or another for the same inputs"});
  fs::last_write_time(files[4], old + std::chrono::seconds(1));
  std::string touched = stamp_key(a, p, exe);
  if (touched == key || touched.empty()) bad.push_back({"stamps", "a source's time ignored"});
  write(files[1], "22");
  fs::last_write_time(files[1], old);
  if (stamp_key(a, p, exe) == touched) bad.push_back({"stamps", "the map's size ignored"});
  write(files[3], "1");  // young: the stamps cannot tell a change within its clock tick
  if (!stamp_key(a, p, exe).empty()) bad.push_back({"stamps", "a key while a source is young"});
  fs::last_write_time(files[3], old);
  write(files[0], "1");
  if (!stamp_key(a, p, exe).empty()) bad.push_back({"stamps", "a key while the rebuilt image is young"});
  fs::last_write_time(files[0], old);
  p.cache_dir = (d / "cache").string();  // the original's inputs then stamped by the snapshot's key
  p.functions = (d / "functions.jsonl").string();
  write(p.functions, "{}");
  if (!stamp_key(a, p, exe).empty()) bad.push_back({"stamps", "a key while an original's input is young"});
  std::error_code ec;
  fs::remove_all(d, ec);
  return bad;
}

}  // namespace

int write_code_store(const std::string& path) { return write_other_code_store(path); }

void add_cache_cases(Cases& cases) {
  cases.insert(cases.end(), {
      {"name cache file", nullptr, name_cache},
      {"replay key", nullptr, replay_key},
      {"unit: code store", nullptr, code_store_case},
      {"unit: diff store", nullptr, diff_store_case},
      {"unit: sources cache", nullptr, source_cache_case},
      {"unit: replay record", nullptr, replay_record},
      {"unit: stamp key", nullptr, stamp_keys},
  });
}

}  // namespace verifier::test
