#include "replay.hpp"

#include <chrono>
#include <cstring>
#include <filesystem>
#include <limits>
#include <memory>

#include "content_hash.hpp"
#include "inputs.hpp"
#include "sha256.hpp"

namespace verifier {

namespace {

// a key's field: its length, then its bytes (no two lists of fields hash alike)
void add_field(Sha256& h, std::string_view data) {
  u64 n = data.size();
  char len[8];
  std::memcpy(len, &n, 8);
  h.update(std::string_view(len, 8));
  h.update(data);
}

}  // namespace

std::vector<std::string> source_files(const Args& a) {
  std::vector<std::string> out;
  for (auto& top : a.src) for (auto& f : list_files(top)) out.push_back(std::move(f.path));
  return out;
}

std::string run_key(const Args& a, const Config& p, const std::string& verifier, const std::vector<std::string>& sources,
                    const std::function<std::string(const std::string&)>& hash) {
  Sha256 h;
  auto add = [&](std::string_view data) { add_field(h, data); };
  add("verifier 5");
  add(verifier);
  std::vector<std::string> files{a.rebuilt, a.map, a.matched.value_or(""), p.undname};
  // the original and the exports: a run that reads them only through the snapshot (a cache, and none of them changed
  // within two seconds) is keyed by the snapshot's key; otherwise by their contents
  std::string snapshot = p.cache_dir.empty() ? std::string() : Original::snapshot_key(p);
  if (snapshot.empty()) for (auto* f : p.snapshot_inputs()) files.push_back(*f);
  else add(snapshot);
  files.insert(files.end(), sources.begin(), sources.end());
  for (auto& f : files) {
    add(f);
    std::string digest = f.empty() ? "" : hash(f);
    add(digest.empty() ? std::string("\0absent", 7) : digest);
  }
  return h.hexdigest();
}

std::string run_key(const Args& a, const Config& p, const std::string& verifier) {
  return run_key(a, p, verifier, source_files(a), content_hash_file_if_present);
}

std::string stamp_key(const Args& a, const Config& p, const std::string& exe) {
  std::vector<ListedFile> sources;
  for (auto& top : a.src)
    for (auto& f : list_files(top)) sources.push_back(std::move(f));
  return stamp_key(a, p, exe, sources, two_seconds_ago());
}

std::string stamp_key(const Args& a, const Config& p, const std::string& exe, const std::vector<ListedFile>& sources,
                      i64 recent) {
  Sha256 h;
  auto add = [&](std::string_view data) { add_field(h, data); };
  bool racy = false;
  auto stamp = [&](const std::string& f) {
    i64 t = std::numeric_limits<i64>::min();   // none for an absent file (the clock's epoch may make times negative)
    add(f.empty() ? "" : file_stamp(f, &t));
    racy |= t >= recent;
  };
  add("verifier stamps 2");
  stamp(exe);
  for (auto* f : {&a.rebuilt, &a.map, &p.undname}) stamp(*f);
  stamp(a.matched.value_or(""));
  if (p.cache_dir.empty())
    for (auto* f : p.snapshot_inputs()) stamp(*f);
  else
    add(Original::snapshot_key(p));
  for (auto& f : sources) {
    add(f.path);
    add(std::to_string(f.size) + "\t" + std::to_string(f.time));
    racy |= f.time >= recent;
  }
  return racy ? "" : h.hexdigest();
}

std::string command_key(const std::vector<std::string>& args, const Config& p) {
  Sha256 h;
  for (auto& s : args) add_field(h, s);
  add_field(h, p.root);
  add_field(h, sha256_file_if_present(p.file));
  return h.hexdigest();
}

// the record: a version line, the command, the rebuilt image's stamp, all the inputs' stamps ("-" for none), the
// rebuilt image's content hash, the key, the exit status, then stdout and the report, each after its length. Checked in
// that order: another command does not replay; the stamps, from metadata alone (all of them only when the image's
// agrees: after a link it does not); when they differ, the image's hash (a replay needs the same image), and only when
// that agrees the key, which hashes every input.
bool load_last(const std::string& path, const std::string& command, const std::string& image_stamp,
               const std::function<std::string()>& stamps, const std::function<std::string()>& image,
               const std::function<std::string()>& key, Last& last) {
  if (!file_exists(path)) return false;
  std::unique_ptr<MappedFile> file;   // released before save_last renames a new record over it
  try { file = std::make_unique<MappedFile>(path); } catch (...) { return false; }
  std::string_view d = file->view();
  size_t p = 0;
  auto line = [&](std::string_view& v) {
    size_t e = d.find('\n', p);
    if (e == std::string_view::npos) return false;
    v = d.substr(p, e - p);
    p = e + 1;
    return true;
  };
  std::string_view version, rec_command, rec_image_stamp, rec_stamps, rec_image, rec_key;
  if (!line(version) || version != "verifier-last 7" || !line(rec_command) || rec_command != command ||
      !line(rec_image_stamp) || !line(rec_stamps) || !line(rec_image) || !line(rec_key))
    return false;
  last.by_stamps = rec_image_stamp == image_stamp && rec_stamps != "-" && rec_stamps == stamps();
  if (!last.by_stamps && (rec_image != image() || rec_key != key())) return false;
  auto num = [&](u64& v) {
    std::string_view s;
    if (!line(s)) return false;
    v = std::strtoull(std::string(s).c_str(), nullptr, 10);
    return true;
  };
  u64 r, no, nr;
  if (!num(r) || !num(no) || p + no > d.size()) return false;
  last.out = std::string(d.substr(p, no));
  p += no;
  if (!num(nr) || p + nr != d.size()) return false;
  last.report = std::string(d.substr(p, nr));
  last.rc = int(r);
  return true;
}

void save_last(const std::string& path, const std::string& command, const std::string& image_stamp, const std::string& stamps,
               const std::string& image, const std::string& key, const std::string& out, const std::string& report, int rc) {
  std::string rec;   // built in place: the output and the report are megabytes
  rec.reserve(256 + command.size() + stamps.size() + out.size() + report.size());
  for (std::string_view part : {std::string_view("verifier-last 7\n"), std::string_view(command), std::string_view("\n"),
                                std::string_view(image_stamp), std::string_view("\n"),
                                stamps.empty() ? std::string_view("-") : std::string_view(stamps), std::string_view("\n"), std::string_view(image),
                                std::string_view("\n"), std::string_view(key), std::string_view("\n")})
    rec += part;
  rec += std::to_string(rc) + "\n" + std::to_string(out.size()) + "\n";
  rec += out;
  rec += std::to_string(report.size()) + "\n";
  rec += report;
  write_file_atomic(path, rec);
}

}  // namespace verifier
