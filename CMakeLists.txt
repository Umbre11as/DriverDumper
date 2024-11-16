cmake_minimum_required(VERSION 3.26)
include("${CMAKE_CURRENT_LIST_DIR}/cmake/flags.cmake")
project(DriverDumper)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")
find_package(WDK REQUIRED)

file(GLOB_RECURSE SOURCES "src/*.cpp")

wdk_add_driver(DriverDumper ${SOURCES})

target_include_directories(DriverDumper PRIVATE "thirdparty/Zydis/include")
target_link_libraries(DriverDumper "${CMAKE_CURRENT_LIST_DIR}/thirdparty/Zydis/lib/Zydis.lib")

target_include_directories(DriverDumper PRIVATE "thirdparty/kCaveHook/include")
target_link_libraries(DriverDumper "${CMAKE_CURRENT_LIST_DIR}/thirdparty/kCaveHook/lib/kCaveHook.lib")
