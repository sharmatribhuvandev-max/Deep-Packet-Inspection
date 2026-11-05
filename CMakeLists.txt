cmake_minimum_required(VERSION 3.14)
project(DeepPacketInspection VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release)
endif()

find_package(Threads REQUIRED)

add_library(dpi_core STATIC
    src/classify.cpp
    src/decode.cpp
    src/engine.cpp
    src/flow.cpp
    src/inspect.cpp
    src/ip.cpp
    src/pcap.cpp
    src/report.cpp
    src/rules.cpp
    src/table.cpp
)
target_include_directories(dpi_core PUBLIC include)
target_link_libraries(dpi_core PUBLIC Threads::Threads)
if(MSVC)
    target_compile_options(dpi_core PRIVATE /W4 /utf-8)
else()
    target_compile_options(dpi_core PRIVATE -Wall -Wextra -pedantic)
endif()

add_executable(dpi src/main.cpp)
target_link_libraries(dpi PRIVATE dpi_core)

add_executable(dpi_tests tests/test_main.cpp)
target_link_libraries(dpi_tests PRIVATE dpi_core)

# With MinGW, bundle the C++ runtime so the .exe runs without MSYS2's DLLs.
if(MINGW)
    target_link_options(dpi PRIVATE -static)
    target_link_options(dpi_tests PRIVATE -static)
endif()

enable_testing()
add_test(NAME unit_tests COMMAND dpi_tests)
