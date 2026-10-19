#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>

namespace sigscan {

// Read-only handle for one input file. On POSIX the file is opened with O_NOFOLLOW (unless the
// caller allows symlinks) and O_NONBLOCK, then checked with fstat, so a path swapped for a
// symlink or FIFO after the directory walk is refused instead of followed or blocked on.
class InputFile {
 public:
  InputFile() = default;
  InputFile(const InputFile&) = delete;
  InputFile& operator=(const InputFile&) = delete;
  InputFile(InputFile&& other) noexcept;
  InputFile& operator=(InputFile&& other) noexcept;
  ~InputFile();

  // Returns an error message, or std::nullopt on success.
  std::optional<std::string> open(const std::filesystem::path& path, bool allow_symlink);

  [[nodiscard]] std::uint64_t size() const { return size_; }

  // Reads up to buffer.size() bytes; 0 means end of file. Throws std::runtime_error on failure.
  std::size_t read(std::span<std::uint8_t> buffer) const;

 private:
  void close();
#ifdef _WIN32
  void* stream_ = nullptr;  // std::FILE*
#else
  int fd_ = -1;
#endif
  std::uint64_t size_ = 0;
};

struct TextFile {
  std::string data;
  std::string error;  // empty on success
};

// Reads a whole small file (rules, config) after checking it is a regular file within the cap.
[[nodiscard]] TextFile read_text_file(const std::filesystem::path& path, std::uint64_t max_bytes);

}  // namespace sigscan
