cmake_minimum_required(VERSION 2.8)
project(libhelium)
set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake-scripts)

include(CheckIncludeFiles)

# Build with blocks by default. If you don't have clang it'll whine at you.
option(BLOCKS "BLOCKS" ON)
# Don't build tests by default
option(ENABLE_TESTS "ENABLE_TESTS" FALSE)

set(VERSION_MAJOR "0")
set(VERSION_MINOR "0")
set(VERSION_PATCH "1")
set(VERSION "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}")
add_definitions(-DLIBHELIUM_VERSION="${VERSION}")
add_definitions(-D_GNU_SOURCE) # you need this or libuv will not be happy

set(CMAKE_C_FLAGS "-Wall -std=c11 -funsigned-char -I../")

find_package(uv)
find_package(crypto)

if(BLOCKS AND NOT APPLE)
  find_package(blocksruntime)
endif(BLOCKS AND NOT APPLE)

if(ENABLE_TESTS)
  find_package(cunit)
endif(ENABLE_TESTS)

IF(BLOCKS)
  SET(HELIUM_LIBS ${HELIUM_LIBS} ${CBLOCKS_LIBRARIES})
  SET(HELIUM_INCLUDES ${HELIUM_LIBS} ${CBLOCKS_INCLUDE_DIR})
  SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fblocks")
ENDIF(BLOCKS)

include_directories(${HELIUM_INCLUDES})
link_directories(${HELIUM_LIBS})

set(HELIUM_SOURCE_FILES
  logging.c
  helium.c)

add_library(helium STATIC ${HELIUM_SOURCE_FILES})

# fPIC is needed to link a static lib to a shared object
# TODO: I can't figure out how to use target_compile_options, but we should
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

