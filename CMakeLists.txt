cmake_minimum_required(VERSION 2.8)
project(libhelium)

set(VERSION_MAJOR "0")
set(VERSION_MINOR "0")
set(VERSION_PATCH "1")
set(VERSION "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}")
add_definitions(-DLIBHELIUM_VERSION="${VERSION}")
add_definitions(-D_GNU_SOURCE) # you need this or libuv will not be happy

# we should use 
set(CMAKE_C_FLAGS "-Wall -std=c11 -L/usr/local/lib -luv")

add_executable(helium helium.c)
# add_library(helium STATIC helium.c)

install(TARGETS helium DESTINATION lib)
