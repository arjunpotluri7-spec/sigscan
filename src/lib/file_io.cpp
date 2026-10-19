#include "sigscan/file_io.hpp"

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <sys/stat.h>
#include <sys/types.h>
#include <cstdio>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace sigscan {
namespace {

std::string errno_message(int err) {
  return std::generic_category().message(err);
}

}  // namespace

#ifdef _WIN32
InputFile::InputFile(InputFile&& other) noexcept
    : stream_(std::exchange(other.stream_, nullptr)), size_(other.size_) {}
#else
InputFile::InputFile(InputFile&& other) noexcept
    : fd_(std::exchange(other.fd_, -1)), size_(other.size_) {}
#endif

InputFile& InputFile::operator=(InputFile&& other) noexcept {
  if (this != &other) {
    close();
#ifdef _WIN32
    stream_ = other.stream_;
    other.stream_ = nullptr;
#else
    fd_ = other.fd_;
    other.fd_ = -1;
#endif
    size_ = other.size_;
  }
  return *this;
}

InputFile::~InputFile() {
  close();
}

void InputFile::close() {
#ifdef _WIN32
  if (stream_ != nullptr) {
    std::fclose(static_cast<std::FILE*>(stream_));
    stream_ = nullptr;
  }
#else
  if (fd_ >= 0) {
    ::close(fd_);
    fd_ = -1;
  }
#endif
}

#ifdef _WIN32

std::optional<std::string> InputFile::open(const std::filesystem::path& path, bool allow_symlink) {
  close();
  std::error_code ec;
  const auto status = std::filesystem::symlink_status(path, ec);
  if (ec) {
    return "cannot open: " + ec.message();
  }
  if (!allow_symlink && std::filesystem::is_symlink(status)) {
    return "refusing to follow symlink";
  }
  if (!std::filesystem::is_regular_file(path, ec)) {
    return "not a regular file";
  }
  std::FILE* f = _wfopen(path.c_str(), L"rb");
  if (f == nullptr) {
    return "cannot open: " + errno_message(errno);
  }
  stream_ = f;
  size_ = std::filesystem::file_size(path, ec);
  return std::nullopt;
}

std::size_t InputFile::read(std::span<std::uint8_t> buffer) const {
  auto* f = static_cast<std::FILE*>(stream_);
  const std::size_t n = std::fread(buffer.data(), 1, buffer.size(), f);
  if (n == 0 && std::ferror(f) != 0) {
    throw std::runtime_error("read error");
  }
  return n;
}

#else

std::optional<std::string> InputFile::open(const std::filesystem::path& path, bool allow_symlink) {
  close();
  // O_NONBLOCK keeps open() from hanging on a FIFO; regular-file reads ignore it.
  // NOLINTNEXTLINE(hicpp-signed-bitwise,bugprone-signed-bitwise): POSIX flags are int by spec.
  const int flags = O_RDONLY | O_NONBLOCK | O_CLOEXEC | (allow_symlink ? 0 : O_NOFOLLOW);
  const int fd = ::open(path.c_str(), flags);  // NOLINT(cppcoreguidelines-pro-type-vararg)
  if (fd < 0) {
    const int err = errno;
    if (err == ELOOP && !allow_symlink) {
      return "refusing to follow symlink";
    }
    return "cannot open: " + errno_message(err);
  }
  struct stat st{};
  if (::fstat(fd, &st) != 0) {
    const int err = errno;
    ::close(fd);
    return "cannot stat: " + errno_message(err);
  }
  if (!S_ISREG(st.st_mode)) {
    ::close(fd);
    return "not a regular file";
  }
  fd_ = fd;
  size_ = st.st_size > 0 ? static_cast<std::uint64_t>(st.st_size) : 0;
  return std::nullopt;
}

std::size_t InputFile::read(std::span<std::uint8_t> buffer) const {
  for (;;) {
    const ssize_t n = ::read(fd_, buffer.data(), buffer.size());
    if (n >= 0) {
      return static_cast<std::size_t>(n);
    }
    if (errno == EINTR) {
      continue;
    }
    throw std::runtime_error("read error: " + errno_message(errno));
  }
}

#endif

TextFile read_text_file(const std::filesystem::path& path, std::uint64_t max_bytes) {
  TextFile result;
  InputFile file;
  if (auto err = file.open(path, /*allow_symlink=*/true)) {
    result.error = *err;
    return result;
  }
  if (file.size() > max_bytes) {
    result.error = "file is larger than the " + std::to_string(max_bytes) + " byte limit";
    return result;
  }
  std::vector<std::uint8_t> buffer(std::size_t{64} * 1024);
  try {
    for (;;) {
      const std::size_t n = file.read(buffer);
      if (n == 0) {
        break;
      }
      if (result.data.size() + n > max_bytes) {
        result.data.clear();
        result.error = "file is larger than the " + std::to_string(max_bytes) + " byte limit";
        return result;
      }
      result.data.append(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(n));
    }
  } catch (const std::runtime_error& e) {
    result.data.clear();
    result.error = e.what();
  }
  return result;
}

}  // namespace sigscan
