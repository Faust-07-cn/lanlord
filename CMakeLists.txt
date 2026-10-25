cmake_minimum_required(VERSION 3.20)
project(lanmgr C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

file(GLOB_RECURSE LANMGR_SOURCES CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/src/*.c)
list(APPEND LANMGR_SOURCES ${CMAKE_SOURCE_DIR}/third_party/cJSON/cJSON.c)

include_directories(
  ${CMAKE_SOURCE_DIR}/src
  ${CMAKE_SOURCE_DIR}/third_party/cJSON
  ${CMAKE_SOURCE_DIR}/third_party/civetweb
)

add_executable(lanmgr ${LANMGR_SOURCES} ${CMAKE_SOURCE_DIR}/third_party/cJSON/cJSON.c)

target_compile_options(lanmgr PRIVATE -Wall -Wextra)

if(WIN32)
  target_link_libraries(lanmgr ws2_32 iphlpapi crypt32 winhttp advapi32 user32 shell32 bcrypt)
endif()

enable_testing()
add_subdirectory(tests)
