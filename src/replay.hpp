// The replay record: a run's output, report and exit status, kept beside the rebuilt image under the inputs it read,
// and the keys a later run is compared by (the command; the inputs' stamps; their contents).
#pragma once
#include <functional>
#include <string>
#include <vector>

#include "annotations.hpp"
#include "args.hpp"
#include "config.hpp"

namespace verifier {

constexpr const char* LAST_RUN = "verifier-last.txt";  // the record's name, beside the rebuilt image

std::vector<std::string> source_files(const Args& a);  // the files under --src, in list_files order

// The replay record's command: the arguments, the root and the configuration's contents (a caller may write the
// configuration before every run). A record replays only its own command, so the keys below hold only the inputs.
std::string command_key(const std::vector<std::string>& args, const Config& p);
// the replay key: the verifier (the executable's hash) and every input file it reads, each by its content hash (`hash`
// gives a file's, "" when it is absent; `sources` lists the files under --src in list_files order). With a cache the
// original and the exports are read only through the snapshot: its key stands for them.
std::string run_key(const Args& a, const Config& p, const std::string& verifier,
                    const std::vector<std::string>& sources,
                    const std::function<std::string(const std::string&)>& hash);
// the same, listing --src and hashing every file
std::string run_key(const Args& a, const Config& p, const std::string& verifier);
// The replay's first check, from metadata alone: the verifier's and every input file's path, size and modification
// time. "" when an input changed within the last two seconds: a change in the same tick of the file clock could leave
// its time and size as they were, so such inputs are checked by contents (run_key) instead.
std::string stamp_key(const Args& a, const Config& p, const std::string& exe);
// the same from the sources' listing (list_files of each --src, in order), "" when an input is not older than `recent`
// (the file clock's ticks)
std::string stamp_key(const Args& a, const Config& p, const std::string& exe, const std::vector<ListedFile>& sources,
                      i64 recent);

// The replay record beside the rebuilt image: what a run printed, its exit status and its report's content hash (the
// report itself is the --json file it wrote), under the inputs it read.
struct Last {
  std::string out, report_hash;  // report_hash "" when the run wrote no report
  int rc = 0;
  bool by_stamps = false;  // replayed by the stamps (else by the contents: the record's stamps are stale)
};
// the record at `path`, when it is this command's and its inputs are as they were (the callbacks give this run's
// stamps, image hash and key, computed only when needed)
bool load_last(const std::string& path, const std::string& command, const std::string& image_stamp,
               const std::function<std::string()>& stamps, const std::function<std::string()>& image,
               const std::function<std::string()>& key, Last& last);
void save_last(const std::string& path, const std::string& command, const std::string& image_stamp,
               const std::string& stamps, const std::string& image, const std::string& key, const std::string& out,
               const std::string& report_hash, int rc);

}  // namespace verifier
