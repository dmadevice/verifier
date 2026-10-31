#include "cache_file.hpp"

#include <filesystem>

namespace verifier {

std::string cache_header(std::string_view magic, std::string_view key) {
  return std::string(magic) + std::string(key) + "\n";
}

std::unique_ptr<const MappedFile> open_cache_file(const std::string& path, std::string_view header) {
  if (path.empty() || !file_exists(path)) return nullptr;
  std::unique_ptr<const MappedFile> f;
  try {
    f = std::make_unique<const MappedFile>(path);
  } catch (...) {
    return nullptr;
  }
  if (f->view().substr(0, header.size()) != header) return nullptr;
  return f;
}

bool write_cache_file(const std::string& path, std::string_view data) {
  std::error_code ec;
  std::filesystem::path dir = std::filesystem::path(path).parent_path();
  if (!dir.empty()) std::filesystem::create_directories(dir, ec);
  return write_file_atomic(path, data);
}

}  // namespace verifier
