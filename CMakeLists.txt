cmake_minimum_required(VERSION 2.8)
project(libhelium)

set(CMAKE_C_COMPILER "clang")
set(VERSION_MAJOR "0")
set(VERSION_MINOR "0")
set(VERSION_PATCH "1")
set(VERSION "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}")
add_definitions(-DLIBHELIUM_VERSION="${VERSION}")
add_definitions(-D_GNU_SOURCE) # you need this or libuv will not be happy
add_definitions(-DHAVE_BLOCKS=1) # for now
set(CMAKE_SHARED_LINKER_FLAGS "-luv -lBlocksRuntime")

# we should use 
set(CMAKE_C_FLAGS "-Wall -std=c11 -g -fblocks")
link_directories(/usr/local/lib)
add_library(helium STATIC helium_api.c)
target_link_libraries(helium uv BlocksRuntime)

add_executable(helium_test test.c)
target_link_libraries(helium_test helium.a)
target_link_libraries(helium_test uv BlocksRuntime)
set_target_properties(helium_test PROPERTIES LINK_FLAGS "-L.")


install(TARGETS helium DESTINATION lib)
