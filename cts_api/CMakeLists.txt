# ==============================================================================
# PROJECT: CTS API - Zero Trust Engine Gateway
# COPYRIGHT: (c) 2026 Cel-Tech-Serv Pty Ltd. All Rights Reserved.
# ==============================================================================
cmake_minimum_required(VERSION 3.14...3.30)
project(CTSAPI VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/third_party)
file(MAKE_DIRECTORY ${INCLUDE_DIR}/nlohmann)

if(NOT EXISTS "${INCLUDE_DIR}/nlohmann/json.hpp")
    file(DOWNLOAD "https://github.com/nlohmann/json/releases/download/v3.11.3/json.hpp" "${INCLUDE_DIR}/nlohmann/json.hpp")
endif()

if(NOT EXISTS "${INCLUDE_DIR}/httplib.h")
    file(DOWNLOAD "https://raw.githubusercontent.com/yhirose/cpp-httplib/v0.14.1/httplib.h" "${INCLUDE_DIR}/httplib.h")
endif()

find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED) 

pkg_check_modules(SODIUM REQUIRED libsodium)
pkg_check_modules(PQ REQUIRED libpq)
# NEW: Tell CMake to locate the C++ PostgreSQL wrapper
pkg_check_modules(PQXX REQUIRED libpqxx) 

file(GLOB SOURCES "src/*.cpp")
add_executable(cts_api ${SOURCES})

# NEW: Include and link the PQXX directories and libraries
target_include_directories(cts_api PRIVATE ${INCLUDE_DIR} ${SODIUM_INCLUDE_DIRS} ${PQ_INCLUDE_DIRS} ${PQXX_INCLUDE_DIRS})
target_link_libraries(cts_api PRIVATE ${PQXX_LIBRARIES} ${PQ_LIBRARIES} ${SODIUM_LIBRARIES} PocoNetSSL PocoNet PocoCrypto PocoFoundation PocoUtil)