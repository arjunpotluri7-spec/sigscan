// libFuzzer harness: arbitrary bytes as a rule file. Parsing, diagnostics formatting,
// compilation and a scan of the input itself must never crash, hang or trip a sanitizer.
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>

#include "sigscan/ruleset.hpp"
#include "sigscan/scanner.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size > 64 * 1024) {
    return 0;
  }
  const std::string_view source(reinterpret_cast<const char*>(data), size);
  sigscan::RulesetBuilder builder;
  builder.add_source(source, "fuzz.sig");
  for (const auto& d : builder.diagnostics()) {
    (void)d.format();
  }
  sigscan::CompileOptions options;
  options.max_table_bytes = 16U * 1024 * 1024;
  const sigscan::CompileResult compiled = builder.compile(options);
  if (!compiled.ruleset) {
    return 0;
  }
  sigscan::ScanOptions scan_options;
  scan_options.chunk_size = 1 + (size % 97);
  const sigscan::Scanner scanner(compiled.ruleset, scan_options);
  (void)scanner.scan_buffer(std::span<const std::uint8_t>(data, size));
  return 0;
}
