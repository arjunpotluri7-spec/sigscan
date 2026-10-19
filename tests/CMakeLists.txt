include(FetchContent)

set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG v1.18.0
  GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(googletest)

add_executable(sigscan_tests
  test_cli.cpp
  test_json.cpp
  test_lexer.cpp
  test_matcher.cpp
  test_parser.cpp
  test_samples.cpp
  test_scanner.cpp
  test_walker.cpp
)
target_link_libraries(sigscan_tests PRIVATE sigscan_cli sigscan_lib sigscan_flags GTest::gtest_main)
target_compile_definitions(sigscan_tests PRIVATE SIGSCAN_SOURCE_DIR="${PROJECT_SOURCE_DIR}")

include(GoogleTest)
gtest_discover_tests(sigscan_tests DISCOVERY_TIMEOUT 60 WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})

# The committed sample files must be exactly what samples/generate.py produces.
find_package(Python3 COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND)
  add_test(NAME samples_generate_check
           COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/samples/generate.py --check)
endif()
