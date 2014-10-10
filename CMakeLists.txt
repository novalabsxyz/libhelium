cmake_minimum_required(VERSION 2.8)
project(libhelium)
SET(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake-scripts)

include(CheckIncludeFiles)

# Build with blocks by default. If you don't have clang it'll whine at you.
option(BLOCKS "BLOCKS" ON)

set(VERSION_MAJOR "0")
set(VERSION_MINOR "0")
set(VERSION_PATCH "1")
set(VERSION "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}")
add_definitions(-DLIBHELIUM_VERSION="${VERSION}")
add_definitions(-D_GNU_SOURCE) # you need this or libuv will not be happy

set(CMAKE_C_FLAGS "-Wall -std=c11 -funsigned-char")

include_directories(/usr/local/include)
link_directories(/usr/local/lib)

find_package(libuv)

check_include_files("stdatomic.h" HAVE_SYS_STDATOMIC)

if (APPLE)
  # use homebrew openssl not the system one
  include_directories(/usr/local/opt/openssl/include)
  link_directories(/usr/local/opt/openssl/lib)
endif (APPLE)

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
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fblocks -fsanitize=undefined")
  target_link_libraries(helium uv BlocksRuntime)
  target_link_libraries(helium_test uv BlocksRuntime)
else()
  add_definitions(-DHAVE_BLOCKS=0)
  set(CMAKE_SHARED_LINKER_FLAGS "-luv -lcrypto")
  target_link_libraries(helium uv)
  target_link_libraries(helium_test uv)
endif(CMAKE_C_COMPILER_ID MATCHES "clang")

install(TARGETS helium DESTINATION lib)

install(FILES helium.h DESTINATION include)

find_package(Doxygen)
if (DOXYGEN_FOUND)
  configure_file(${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile.out @ONLY)
  add_custom_target(doc ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile.out WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Generating API documentation with Doxygen" )
endif(DOXYGEN_FOUND)

find_package(CMake)
