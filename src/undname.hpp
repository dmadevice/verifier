// Running MSVC's undname (or a program printing its output format) to undecorate names.
#pragma once
#include <string>
#include <unordered_map>
#include <vector>

namespace verifier {

// {decorated: undecorated} for the names starting with '?', by running `undname` in batches, one after another
std::unordered_map<std::string, std::string> undecorate(const std::vector<std::string>& names,
                                                        const std::string& undname);

}  // namespace verifier
