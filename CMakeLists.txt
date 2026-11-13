cmake_minimum_required(VERSION 3.23)
project(verifier LANGUAGES C CXX)

# fadec (x86-64 decoder), fetched at configure time and linked statically; its build generates the decode
# tables with Python 3. Set FETCHCONTENT_SOURCE_DIR_FADEC to a local checkout for offline builds.
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

# Reproducible builds: the same sources and compiler give the same binary wherever the tree is (a consumer may lock
# the binary by its hash). MSVC stamps a time into objects and the image unless told not to; GCC and Clang embed
# source paths only in debug information and assertions, which the prefix maps make relative.
if(WIN32)
  add_compile_definitions(_CRT_SECURE_NO_WARNINGS)  # getenv
endif()
if(MSVC)
  add_compile_options(/Brepro)
  add_link_options(/Brepro)
else()
  add_compile_options(-ffile-prefix-map=${CMAKE_SOURCE_DIR}=. -ffile-prefix-map=${CMAKE_BINARY_DIR}=build)
endif()

include(FetchContent)
set(FADEC_ARCHMODE only64 CACHE STRING "" FORCE)
set(FADEC_ENCODE OFF CACHE BOOL "" FORCE)
set(FADEC_ENCODE2 OFF CACHE BOOL "" FORCE)
FetchContent_Declare(fadec
  GIT_REPOSITORY https://github.com/aengelke/fadec.git
  GIT_TAG c9f78f532b9004de278489019ab2c6c28ae9746e)
FetchContent_MakeAvailable(fadec)

set(CORE_SOURCES
  src/util.cpp src/problem.cpp src/json.cpp src/sha256.cpp src/pe.cpp src/x64.cpp src/names.cpp src/demangle.cpp src/annotations.cpp
  src/config.cpp src/inputs.cpp src/matching.cpp src/compare.cpp src/compare_refs.cpp src/compare_eh.cpp src/layouts.cpp src/policy.cpp src/pairing.cpp src/align.cpp src/report.cpp src/diff_store.cpp src/result.cpp src/verify.cpp src/cache_file.cpp src/code_store.cpp src/args.cpp src/timing.cpp src/name_cache.cpp)
add_library(verifier_core STATIC ${CORE_SOURCES})
target_include_directories(verifier_core PUBLIC src)
target_link_libraries(verifier_core PUBLIC fadec)
if(MSVC)
  target_compile_options(verifier_core PUBLIC /W3 /utf-8)
else()
  target_compile_options(verifier_core PUBLIC -Wall -Wextra -Wno-unused-parameter)
endif()

add_executable(verifier src/main.cpp)
target_link_libraries(verifier PRIVATE verifier_core)

enable_testing()
add_executable(verifier-tests tests/main.cpp tests/fixture_cases.cpp tests/names_test.cpp tests/demangle_test.cpp tests/report_test.cpp
  tests/compare_test.cpp tests/eh_test.cpp tests/pairing_test.cpp tests/inputs_test.cpp tests/cache_test.cpp tests/util_test.cpp)
target_include_directories(verifier-tests PRIVATE tests)
target_link_libraries(verifier-tests PRIVATE verifier_core)
target_compile_definitions(verifier-tests PRIVATE VERIFIER_FIXTURES="${CMAKE_CURRENT_SOURCE_DIR}/tests/data/fixtures.json")
add_test(NAME fixtures COMMAND verifier-tests)

# fixture-dump: a case of tests/data/fixtures.json printed readably (disassembly, data, mapping, expected problems)
add_executable(fixture-dump tests/fixture_dump.cpp)
target_link_libraries(fixture-dump PRIVATE verifier_core)
target_compile_definitions(fixture-dump PRIVATE VERIFIER_FIXTURES="${CMAKE_CURRENT_SOURCE_DIR}/tests/data/fixtures.json")

# cmake --build build --target format: the sources formatted by .clang-format
find_program(CLANG_FORMAT clang-format)
if(CLANG_FORMAT)
  file(GLOB FORMATTED ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp ${CMAKE_CURRENT_SOURCE_DIR}/src/*.hpp
       ${CMAKE_CURRENT_SOURCE_DIR}/tests/*.cpp ${CMAKE_CURRENT_SOURCE_DIR}/tests/*.hpp)
  add_custom_target(format COMMAND ${CLANG_FORMAT} -i --style=file ${FORMATTED} WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
endif()
