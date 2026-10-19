#pragma once

#include <cstddef>
#include <functional>

namespace sigscan {

// Runs task(i) for every i in [0, count) on up to `threads` worker threads. Each index runs
// exactly once; callers write results into slot i, so output order never depends on scheduling.
// The first exception thrown by a task is rethrown after all workers have stopped.
void run_parallel(std::size_t count, unsigned threads,
                  const std::function<void(std::size_t)>& task);

[[nodiscard]] unsigned default_thread_count();

}  // namespace sigscan
