cmake_minimum_required(VERSION 3.20)
project(rmtls_threshold_mlkem_prototype_cpp LANGUAGES C CXX)

include(FetchContent)
include(CTest)
find_package(OpenSSL REQUIRED)

FetchContent_Declare(
    mlkem_native
    URL https://github.com/pq-code-package/mlkem-native/archive/refs/tags/v1.0.0.zip
    URL_HASH SHA256=bb6bee7023e8f25e5aff5146253c5cb2a5797daf7fa873cee651ab1360620527
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(mlkem_native)

if(WIN32 AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    get_filename_component(
        RMTLS_CXX_COMPILER_DIRECTORY
        "${CMAKE_CXX_COMPILER}"
        DIRECTORY
    )

    if(NOT CMAKE_AR OR CMAKE_AR STREQUAL ":" OR
       CMAKE_AR MATCHES "-NOTFOUND$")
        find_program(
            RMTLS_GNU_AR
            NAMES gcc-ar x86_64-w64-mingw32-gcc-ar
                  x86_64-w64-mingw32-ar ar
            HINTS "${RMTLS_CXX_COMPILER_DIRECTORY}"
        )
        if(RMTLS_GNU_AR)
            set(CMAKE_AR "${RMTLS_GNU_AR}" CACHE FILEPATH
                "Archiver used by the selected GNU C++ toolchain" FORCE)
            set(CMAKE_CXX_COMPILER_AR "${RMTLS_GNU_AR}" CACHE FILEPATH
                "C++ archiver used by the selected GNU toolchain" FORCE)
        endif()
    endif()

    if(NOT CMAKE_RANLIB OR CMAKE_RANLIB STREQUAL ":" OR
       CMAKE_RANLIB MATCHES "-NOTFOUND$")
        find_program(
            RMTLS_GNU_RANLIB
            NAMES gcc-ranlib x86_64-w64-mingw32-gcc-ranlib
                  x86_64-w64-mingw32-ranlib ranlib
            HINTS "${RMTLS_CXX_COMPILER_DIRECTORY}"
        )
        if(RMTLS_GNU_RANLIB)
            set(CMAKE_RANLIB "${RMTLS_GNU_RANLIB}" CACHE FILEPATH
                "Ranlib used by the selected GNU C++ toolchain" FORCE)
            set(CMAKE_CXX_COMPILER_RANLIB "${RMTLS_GNU_RANLIB}" CACHE FILEPATH
                "C++ ranlib used by the selected GNU toolchain" FORCE)
        endif()
    endif()
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(WIN32)
    add_compile_definitions(NOMINMAX WIN32_LEAN_AND_MEAN)
endif()

option(RMTLS_WARNINGS_AS_ERRORS "Treat warnings as errors" OFF)

function(rmtls_enable_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
    endif()

    if(RMTLS_WARNINGS_AS_ERRORS)
        if(MSVC)
            target_compile_options(${target} PRIVATE /WX)
        else()
            target_compile_options(${target} PRIVATE -Werror)
        endif()
    endif()
endfunction()

set(RMTLS_THRESHOLD_MLKEM_SOURCES
    src/sharing.cpp
    src/mlkem_adapter.cpp
    src/mlkem_native_bridge.c
    src/transcript.cpp
    src/assistant.cpp
    src/combiner.cpp
    src/front_service.cpp
    src/public_log.cpp
    src/authkem_baseline.cpp
)

add_library(rmtls_mlkem_native_512 STATIC
    "${mlkem_native_SOURCE_DIR}/mlkem/mlkem_native.c"
)
target_include_directories(rmtls_mlkem_native_512 PRIVATE
    "${mlkem_native_SOURCE_DIR}/mlkem"
)
target_compile_definitions(rmtls_mlkem_native_512 PRIVATE
    MLK_CONFIG_PARAMETER_SET=512
    MLK_CONFIG_NAMESPACE_PREFIX=rmtls_mlkem
)

if(WIN32)
    target_link_libraries(rmtls_mlkem_native_512 PRIVATE bcrypt)
endif()

function(add_rmtls_library target)
    add_library(${target} ${RMTLS_THRESHOLD_MLKEM_SOURCES})
    target_include_directories(${target} PUBLIC include)
    target_include_directories(${target} PRIVATE
        "${mlkem_native_SOURCE_DIR}/mlkem"
    )
    target_compile_definitions(${target} PRIVATE
        MLK_CONFIG_PARAMETER_SET=512
        MLK_CONFIG_NAMESPACE_PREFIX=rmtls_mlkem
    )
    target_link_libraries(${target} PRIVATE
        rmtls_mlkem_native_512
        OpenSSL::Crypto
    )
    if(WIN32)
        target_link_libraries(${target} PRIVATE bcrypt)
    endif()
    rmtls_enable_warnings(${target})
endfunction()

add_rmtls_library(rmtls_threshold_mlkem)

if(BUILD_TESTING)
    add_rmtls_library(rmtls_threshold_mlkem_test)
    target_compile_definitions(rmtls_threshold_mlkem_test PUBLIC
        RMTLS_ENABLE_TEST_OBSERVERS=1
    )

    function(add_rmtls_test name source)
        add_executable(${name} ${source})
        target_link_libraries(${name} PRIVATE rmtls_threshold_mlkem_test)
        rmtls_enable_warnings(${name})
        add_test(NAME ${name} COMMAND ${name})
    endfunction()

    add_rmtls_test(test_sharing tests/test_sharing.cpp)
    add_rmtls_test(test_stage_a_inner_decryption tests/test_stage_a_inner_decryption.cpp)
    add_rmtls_test(test_transcript_admission tests/test_transcript_admission.cpp)
    add_rmtls_test(test_leakage_and_branch_hiding tests/test_leakage_and_branch_hiding.cpp)
    add_rmtls_test(test_real_mlkem512 tests/test_real_mlkem512.cpp)
    add_rmtls_test(test_authkem_comparison tests/test_authkem_comparison.cpp)

    add_executable(test_production_api tests/test_production_api.cpp)
    target_link_libraries(test_production_api PRIVATE rmtls_threshold_mlkem)
    rmtls_enable_warnings(test_production_api)
    add_test(NAME test_production_api COMMAND test_production_api)
endif()

if(EXISTS "${CMAKE_SOURCE_DIR}/benchmarks/toy_stage_d_benchmark.cpp")
    add_executable(toy_stage_d_benchmark
        benchmarks/toy_stage_d_benchmark.cpp
    )
    target_link_libraries(toy_stage_d_benchmark PRIVATE rmtls_threshold_mlkem)
    rmtls_enable_warnings(toy_stage_d_benchmark)
endif()

add_executable(run_authkem_comparison
    experiments/run_authkem_comparison.cpp
)
target_link_libraries(run_authkem_comparison PRIVATE rmtls_threshold_mlkem)
rmtls_enable_warnings(run_authkem_comparison)
