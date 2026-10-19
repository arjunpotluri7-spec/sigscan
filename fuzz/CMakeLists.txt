set(SIGSCAN_FUZZ_TARGETS rule_parser matcher)

# Portable smoke drivers: same entry points, deterministic mutations, any compiler.
if(SIGSCAN_BUILD_FUZZ_SMOKE)
  foreach(target IN LISTS SIGSCAN_FUZZ_TARGETS)
    add_executable(fuzz_smoke_${target} fuzz_${target}.cpp smoke_main.cpp)
    target_link_libraries(fuzz_smoke_${target} PRIVATE sigscan_lib)
    add_test(NAME fuzz_smoke_${target}
             COMMAND fuzz_smoke_${target} ${CMAKE_CURRENT_SOURCE_DIR}/corpus/${target} 2000)
  endforeach()
endif()

# Coverage-guided libFuzzer targets (clang with -fsanitize=fuzzer; used in Linux CI).
if(SIGSCAN_ENABLE_FUZZERS)
  include(CheckCXXSourceCompiles)
  set(CMAKE_REQUIRED_FLAGS "-fsanitize=fuzzer")
  set(CMAKE_REQUIRED_LINK_OPTIONS "-fsanitize=fuzzer")
  check_cxx_source_compiles([=[
    #include <cstddef>
    #include <cstdint>
    extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t*, std::size_t) { return 0; }
  ]=] SIGSCAN_HAVE_LIBFUZZER)
  unset(CMAKE_REQUIRED_FLAGS)
  unset(CMAKE_REQUIRED_LINK_OPTIONS)
  if(NOT SIGSCAN_HAVE_LIBFUZZER)
    message(FATAL_ERROR "SIGSCAN_ENABLE_FUZZERS=ON but the compiler does not support "
                        "-fsanitize=fuzzer (Apple clang does not ship libFuzzer).")
  endif()
  foreach(target IN LISTS SIGSCAN_FUZZ_TARGETS)
    add_executable(fuzz_${target} fuzz_${target}.cpp)
    target_compile_options(fuzz_${target} PRIVATE -fsanitize=fuzzer)
    target_link_options(fuzz_${target} PRIVATE -fsanitize=fuzzer)
    target_link_libraries(fuzz_${target} PRIVATE sigscan_lib)
  endforeach()
endif()
