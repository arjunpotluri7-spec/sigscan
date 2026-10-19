cmake_minimum_required(VERSION 3.25)

project(sigscan VERSION 0.1.0 DESCRIPTION "Explainable signature scanner for files" LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(SIGSCAN_BUILD_TESTS "Build the GoogleTest suite" ON)
option(SIGSCAN_WERROR "Treat compiler warnings as errors" OFF)
option(SIGSCAN_ENABLE_FUZZERS "Build libFuzzer harnesses (needs clang with -fsanitize=fuzzer)" OFF)
option(SIGSCAN_BUILD_FUZZ_SMOKE "Build the portable fuzz smoke drivers" ON)
set(SIGSCAN_SANITIZE "" CACHE STRING "Sanitizers to enable, e.g. address,undefined")

# Warnings and sanitizers apply to this project's targets only, never to GoogleTest.
add_library(sigscan_flags INTERFACE)
if(MSVC)
  target_compile_options(sigscan_flags INTERFACE /W4 /permissive-)
  if(SIGSCAN_WERROR)
    target_compile_options(sigscan_flags INTERFACE /WX)
  endif()
else()
  target_compile_options(sigscan_flags INTERFACE -Wall -Wextra -Wpedantic -Wshadow -Wconversion
                                                 -Wsign-conversion -Wnon-virtual-dtor)
  if(SIGSCAN_WERROR)
    target_compile_options(sigscan_flags INTERFACE -Werror)
  endif()
endif()

if(SIGSCAN_SANITIZE)
  add_compile_options(-fsanitize=${SIGSCAN_SANITIZE} -fno-omit-frame-pointer
                      -fno-sanitize-recover=all)
  add_link_options(-fsanitize=${SIGSCAN_SANITIZE})
endif()

if(SIGSCAN_ENABLE_FUZZERS)
  # Coverage instrumentation for the library so libFuzzer can see inside it.
  add_compile_options(-fsanitize=fuzzer-no-link)
endif()

find_package(Threads REQUIRED)

add_library(sigscan_lib STATIC
  src/lib/aho_corasick.cpp
  src/lib/condition.cpp
  src/lib/diagnostics.cpp
  src/lib/file_io.cpp
  src/lib/json_writer.cpp
  src/lib/lexer.cpp
  src/lib/log.cpp
  src/lib/parser.cpp
  src/lib/pattern.cpp
  src/lib/report.cpp
  src/lib/ruleset.cpp
  src/lib/scanner.cpp
  src/lib/walker.cpp
  src/lib/worker_pool.cpp
)
target_include_directories(sigscan_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(sigscan_lib PUBLIC Threads::Threads PRIVATE sigscan_flags)

add_library(sigscan_cli STATIC src/cli/cli.cpp)
target_include_directories(sigscan_cli PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src/cli)
target_link_libraries(sigscan_cli PUBLIC sigscan_lib PRIVATE sigscan_flags)

add_executable(sigscan src/cli/main.cpp)
target_link_libraries(sigscan PRIVATE sigscan_cli sigscan_flags)

include(GNUInstallDirs)
install(TARGETS sigscan RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

enable_testing()

if(SIGSCAN_BUILD_TESTS)
  add_subdirectory(tests)
endif()

if(SIGSCAN_BUILD_FUZZ_SMOKE OR SIGSCAN_ENABLE_FUZZERS)
  add_subdirectory(fuzz)
endif()
