cmake_minimum_required(VERSION 3.20)
project(verifier LANGUAGES C CXX)

# capstone 5.0.9, fetched at configure time and linked statically (x86 only). Set FETCHCONTENT_SOURCE_DIR_CAPSTONE
# to a local checkout for offline builds.
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

include(FetchContent)
set(CAPSTONE_ARCHITECTURE_DEFAULT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_X86_SUPPORT ON CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_STATIC ON CACHE BOOL "" FORCE)
set(CAPSTONE_INSTALL OFF CACHE BOOL "" FORCE)
FetchContent_Declare(capstone
  GIT_REPOSITORY https://github.com/capstone-engine/capstone.git
  GIT_TAG 022575848782a4801fd150fdbc927effcbca0864   # tag 5.0.9
  GIT_SHALLOW FALSE)
FetchContent_MakeAvailable(capstone)

set(CORE_SOURCES
  src/util.cpp src/json.cpp src/sha256.cpp src/pe.cpp src/x64.cpp src/names.cpp src/annotations.cpp
  src/config.cpp src/inputs.cpp src/compare.cpp src/pairing.cpp src/report.cpp src/verify.cpp)
add_library(verifier_core STATIC ${CORE_SOURCES})
target_include_directories(verifier_core PUBLIC src)
target_link_libraries(verifier_core PUBLIC capstone_static)
if(MSVC)
  target_compile_options(verifier_core PUBLIC /W3 /utf-8)
else()
  target_compile_options(verifier_core PUBLIC -Wall -Wextra -Wno-unused-parameter)
endif()

add_executable(verifier src/main.cpp)
target_link_libraries(verifier PRIVATE verifier_core)

add_executable(verifier-compare tools/compare_reports.cpp)
target_link_libraries(verifier-compare PRIVATE verifier_core)

enable_testing()
add_executable(verifier-tests tests/fixtures.cpp)
target_link_libraries(verifier-tests PRIVATE verifier_core)
target_compile_definitions(verifier-tests PRIVATE VERIFIER_FIXTURES="${CMAKE_CURRENT_SOURCE_DIR}/tests/data/fixtures.json")
add_test(NAME fixtures COMMAND verifier-tests)
