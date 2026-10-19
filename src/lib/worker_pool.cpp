#include "sigscan/worker_pool.hpp"

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <exception>
#include <functional>
#include <mutex>
#include <thread>
#include <vector>

namespace sigscan {

unsigned default_thread_count() {
  const unsigned hw = std::thread::hardware_concurrency();
  return std::clamp(hw, 1U, 8U);
}

void run_parallel(std::size_t count, unsigned threads,
                  const std::function<void(std::size_t)>& task) {
  if (count == 0) {
    return;
  }
  const std::size_t workers = std::min<std::size_t>(std::max(threads, 1U), count);
  if (workers == 1) {
    for (std::size_t i = 0; i < count; ++i) {
      task(i);
    }
    return;
  }
  std::atomic<std::size_t> next{0};
  std::atomic<bool> stop{false};
  std::exception_ptr first_error;
  std::mutex error_mutex;
  auto worker = [&] {
    for (;;) {
      if (stop.load(std::memory_order_relaxed)) {
        return;
      }
      const std::size_t i = next.fetch_add(1, std::memory_order_relaxed);
      if (i >= count) {
        return;
      }
      try {
        task(i);
      } catch (...) {
        const std::lock_guard<std::mutex> lock(error_mutex);
        if (!first_error) {
          first_error = std::current_exception();
        }
        stop.store(true, std::memory_order_relaxed);
      }
    }
  };
  std::vector<std::thread> pool;
  pool.reserve(workers);
  for (std::size_t w = 0; w < workers; ++w) {
    pool.emplace_back(worker);
  }
  for (std::thread& t : pool) {
    t.join();
  }
  if (first_error) {
    std::rethrow_exception(first_error);
  }
}

}  // namespace sigscan
