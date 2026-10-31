// Content hashes for the replay record: whether an input is the one the last run read. Not a security measure (the
// original's configured hash is SHA-256): XXH64 under two seeds, 128 bits, several times faster than SHA-256.
#pragma once
#include <string>
#include <string_view>

#include "util.hpp"

namespace verifier {

u64 xxh64(std::string_view data, u64 seed);                         // XXH64 as specified
std::string content_hash(std::string_view data);                    // 32 hex digits
std::string content_hash_file_if_present(const std::string& path);  // "" when the file is absent

}  // namespace verifier
