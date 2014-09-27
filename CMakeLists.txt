cmake_minimum_required(VERSION 2.8)
project(libhelium)

# Build with blocks by default. If you don't have clang it'll whine at you.
option(BLOCKS "BLOCKS" ON)

set(VERSION_MAJOR "0")
set(VERSION_MINOR "0")
set(VERSION_PATCH "1")
set(VERSION "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}")
add_definitions(-DLIBHELIUM_VERSION="${VERSION}")
add_definitions(-D_GNU_SOURCE) # you need this or libuv will not be happy

link_directories(/usr/local/lib)
add_library(helium STATIC logging.c helium.c)
# fPIC is needed to link a static lib to a shared object
set_target_properties(helium PROPERTIES COMPILE_FLAGS "-fPIC")

add_executable(helium_test test.c)
target_link_libraries(helium_test helium.a)
# force helium_test to rebuild if libhelium changes
SET_SOURCE_FILES_PROPERTIES(
  test.c PROPERTIES OBJECT_DEPENDS
  ${CMAKE_CURRENT_BINARY_DIR}/libhelium.a
  )
set_target_properties(helium_test PROPERTIES LINK_FLAGS "-L. -lcrypto")

add_executable(multiloop_test multiloop_test.c)
target_link_libraries(multiloop_test helium.a)
set_target_properties(multiloop_test PROPERTIES LINK_FLAGS "-L. -lcrypto -luv")


if(CMAKE_C_COMPILER_ID MATCHES "clang")
  add_definitions(-DHAVE_BLOCKS=1)
  set(CMAKE_SHARED_LINKER_FLAGS "-luv -lcrypto -lBlocksRuntime")
  set(CMAKE_C_FLAGS "-Wall -std=c11 -fblocks -funsigned-char -fsanitize=undefined")
  target_link_libraries(helium uv BlocksRuntime)
  target_link_libraries(helium_test uv BlocksRuntime)
else()
  add_definitions(-DHAVE_BLOCKS=0)
  set(CMAKE_SHARED_LINKER_FLAGS "-luv -lcrypto")
  set(CMAKE_C_FLAGS "-Wall -std=c11 -funsigned-char")
  target_link_libraries(helium uv)
  target_link_libraries(helium_test uv)
endif(CMAKE_C_COMPILER_ID MATCHES "clang")

install(TARGETS helium DESTINATION lib)

install(FILES helium.h DESTINATION include)
