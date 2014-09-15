cmake_minimum_required(VERSION 2.8)
project(libhelium)

set(VERSION_MAJOR "0")
set(VERSION_MINOR "0")
set(VERSION_PATCH "5")
set(VERSION "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}")

add_library(helium STATIC helium.c)

install(TARGETS helium DESTINATION lib)
