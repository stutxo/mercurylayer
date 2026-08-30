# Set the minimum required version of CMake
cmake_minimum_required(VERSION 3.15)

project(MercuryLockbox VERSION 0.1
                    DESCRIPTION "Mercury Lockbox"
                    LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
include(secp256k1)

option(LOCKBOX_ENABLE_TEST_RNG "Enable deterministic lockbox RNG for tests" OFF)
option(LOCKBOX_ENABLE_GOOGLE_KMS "Build the Google Secret Manager/KMS key manager" OFF)
option(LOCKBOX_BUILD_TESTS "Build Lockbox tests" OFF)
set(LOCKBOX_DATABASE_BACKEND "postgres" CACHE STRING "Lockbox database backend (postgres or sqlite)")
set_property(CACHE LOCKBOX_DATABASE_BACKEND PROPERTY STRINGS postgres sqlite)

if(NOT LOCKBOX_DATABASE_BACKEND STREQUAL "postgres" AND
   NOT LOCKBOX_DATABASE_BACKEND STREQUAL "sqlite")
    message(FATAL_ERROR
        "Unknown LOCKBOX_DATABASE_BACKEND='${LOCKBOX_DATABASE_BACKEND}'; expected postgres or sqlite")
endif()

find_package(Crow CONFIG REQUIRED)
find_package(cpr CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

include(FetchContent)
set(BUILD_TESTING OFF CACHE BOOL "Disable dependency test targets" FORCE)
set(SKIP_BUILD_TEST ON CACHE BOOL "Disable libpqxx test targets" FORCE)

FetchContent_Declare(
    tomlplusplus
    GIT_REPOSITORY https://github.com/marzer/tomlplusplus.git
    GIT_TAG v3.4.0
)
FetchContent_MakeAvailable(tomlplusplus)

set(LOCKBOX_SOURCES
    src/server.cpp
    src/utils.cpp
    src/hashicorp_api_key_manager.cpp
    src/hashicorp_container_key_manager.cpp
    src/filesystem_key_manager.cpp
    src/request_auth.cpp
    src/enclave.cpp
    src/monocypher.c)

set(LOCKBOX_LIBRARIES
    Crow::Crow
    cpr::cpr
    tomlplusplus::tomlplusplus
    secp256k1
    OpenSSL::SSL
    OpenSSL::Crypto)

if(LOCKBOX_DATABASE_BACKEND STREQUAL "postgres")
    FetchContent_Declare(
        libpqxx
        GIT_REPOSITORY https://github.com/jtv/libpqxx.git
        GIT_TAG 7.8.1
    )
    FetchContent_MakeAvailable(libpqxx)
    list(APPEND LOCKBOX_SOURCES src/db_manager.cpp)
    list(APPEND LOCKBOX_LIBRARIES pqxx)
else()
    find_package(SQLite3 REQUIRED)
    list(APPEND LOCKBOX_SOURCES src/sqlite_db_manager.cpp)
    list(APPEND LOCKBOX_LIBRARIES SQLite::SQLite3)
endif()

if(LOCKBOX_ENABLE_GOOGLE_KMS)
    list(APPEND LOCKBOX_SOURCES src/google_key_manager.cpp)
    find_package(google_cloud_cpp_kms REQUIRED)
    find_package(google_cloud_cpp_secretmanager REQUIRED)
    list(APPEND LOCKBOX_LIBRARIES
        google-cloud-cpp::kms
        google-cloud-cpp::secretmanager)
endif()

add_library(LockboxLibrary ${LOCKBOX_SOURCES})
set_source_files_properties(src/monocypher.c PROPERTIES LANGUAGE C)
target_include_directories(LockboxLibrary PUBLIC include)

if(LOCKBOX_ENABLE_TEST_RNG)
    target_compile_definitions(LockboxLibrary PRIVATE LOCKBOX_ENABLE_TEST_RNG=1)
endif()
if(LOCKBOX_ENABLE_GOOGLE_KMS)
    target_compile_definitions(LockboxLibrary PUBLIC LOCKBOX_ENABLE_GOOGLE_KMS=1)
endif()
if(LOCKBOX_DATABASE_BACKEND STREQUAL "sqlite")
    target_compile_definitions(LockboxLibrary PRIVATE LOCKBOX_DATABASE_BACKEND_SQLITE=1)
endif()

target_compile_options(LockboxLibrary PRIVATE
    $<$<COMPILE_LANGUAGE:C>:-std=c11>
    $<$<COMPILE_LANGUAGE:CXX>:-std=c++17>)
target_link_libraries(LockboxLibrary PUBLIC ${LOCKBOX_LIBRARIES})

add_executable(MercuryLockbox src/main.cpp)
target_include_directories(MercuryLockbox PRIVATE include)
target_link_libraries(MercuryLockbox PRIVATE LockboxLibrary)

if(LOCKBOX_BUILD_TESTS)
    enable_testing()
    add_executable(LockboxRequestAuthTests tests/request_auth_test.cpp)
    target_link_libraries(LockboxRequestAuthTests PRIVATE LockboxLibrary)
    add_test(NAME lockbox_request_auth COMMAND LockboxRequestAuthTests)

    if(LOCKBOX_DATABASE_BACKEND STREQUAL "sqlite")
        add_executable(LockboxSQLiteDatabaseTests tests/sqlite_db_manager_test.cpp)
        target_link_libraries(LockboxSQLiteDatabaseTests PRIVATE LockboxLibrary SQLite::SQLite3)
        add_test(NAME lockbox_sqlite_db_manager COMMAND LockboxSQLiteDatabaseTests)
    endif()
endif()
