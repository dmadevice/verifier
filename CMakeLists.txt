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

include(FetchContent)
set(FADEC_ARCHMODE only64 CACHE STRING "" FORCE)
set(FADEC_ENCODE OFF CACHE BOOL "" FORCE)
set(FADEC_ENCODE2 OFF CACHE BOOL "" FORCE)
FetchContent_Declare(fadec
  GIT_REPOSITORY https://github.com/aengelke/fadec.git
  GIT_TAG c9f78f532b9004de278489019ab2c6c28ae9746e)
FetchContent_MakeAvailable(fadec)

set(CORE_SOURCES
  src/util.cpp src/json.cpp src/sha256.cpp src/pe.cpp src/x64.cpp src/names.cpp src/annotations.cpp
  src/config.cpp src/inputs.cpp src/compare.cpp src/pairing.cpp src/report.cpp src/verify.cpp)
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
add_executable(verifier-tests tests/fixtures.cpp)
target_link_libraries(verifier-tests PRIVATE verifier_core)
target_compile_definitions(verifier-tests PRIVATE VERIFIER_FIXTURES="${CMAKE_CURRENT_SOURCE_DIR}/tests/data/fixtures.json")
add_test(NAME fixtures COMMAND verifier-tests)
