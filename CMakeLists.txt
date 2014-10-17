cmake_minimum_required(VERSION 2.8)
project(libhelium)
set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake-scripts)

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

find_package(uv)
find_package(crypto)
find_package(openssl)

if(BLOCKS AND NOT APPLE)
  find_package(blocksruntime)
endif(BLOCKS AND NOT APPLE)

find_package(cunit)

set(HELIUM_INCLUDES
  include
  ${CMAKE_CURRENT_BINARY_DIR}/include/
)

set(HELIUM_LIBS ${OPENSSL_LIBRARIES} ${HELIUM_LIBS} ${UV_LIBRARIES} ${CRYPTO_LIBRARIES} )
set(HELIUM_INCLUDES ${OPENSSL_INCLUDE_DIR} ${HELIUM_INCLUDES} ${UV_INCLUDE_DIR} ${CRYPTO_INCLUDE_DIR} )

if(BLOCKS AND BLOCKS_FOUND)
  set(HELIUM_LIBS ${HELIUM_LIBS} ${CBLOCKS_LIBRARIES})
  set(HELIUM_INCLUDES ${HELIUM_INCLUDES} ${CBLOCKS_INCLUDE_DIR})
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fblocks")
endif(BLOCKS AND BLOCKS_FOUND)

set(HELIUM_SOURCE_FILES
  src/logging.c
  src/helium.c)

set(HELIUM_HEADER_FILES
  include/helium_logging.h
  include/helium.h)

set(HELIUM_TEST_FILES
  tests/test_open_close.c)

if(CMAKE_C_COMPILER_ID MATCHES "clang")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fblocks -fsanitize=undefined")
  add_definitions(-DHAVE_BLOCKS=1)
else()
  add_definitions(-DHAVE_BLOCKS=0)
endif(CMAKE_C_COMPILER_ID MATCHES "clang")

message("HELIUM_INCLUDES are ${HELIUM_INCLUDES}")
message("HELIUM_LIBS ARE ${HELIUM_LIBS}")

add_library(helium STATIC ${HELIUM_SOURCE_FILES})
target_include_directories(helium PUBLIC ${HELIUM_INCLUDES})
target_link_libraries(helium PUBLIC ${HELIUM_LIBS})

# fPIC is needed to link a static lib to a shared object
target_compile_options(helium PUBLIC "-fPIC")

install(TARGETS helium DESTINATION lib)
install(FILES ${HELIUM_HEADER_FILES} DESTINATION include)

set(SAMPLE_INCLUDES
  ${PROJECT_SOURCE_DIR}/include
  ${OPENSSL_INCLUDE_DIR}
  ${UV_INCLUDE_DIR}
  ${CRYPTO_INCLUDE_DIR})

set(SAMPLE_LIBRARIES
  ${CMAKE_CURRENT_BINARY_DIR}/libhelium.a
  ${OPENSSL_LIBRARIES}
  ${UV_LIBRARIES}
  ${CRYPTO_LIBRARIES})

set(TEST_LIBRARIES
  ${CUNIT_LIBRARY}
  ${SAMPLE_LIBRARIES})

add_executable(shell samples/shell.c)
add_dependencies(shell helium)
target_include_directories(shell PUBLIC ${SAMPLE_INCLUDES})
target_link_libraries(shell PUBLIC ${SAMPLE_LIBRARIES})

add_executable(multiloop_test samples/multiloop_test.c)
add_dependencies(multiloop_test helium)
target_include_directories(multiloop_test PUBLIC ${SAMPLE_INCLUDES})
target_link_libraries(multiloop_test PUBLIC ${SAMPLE_LIBRARIES})

if(CUNIT_FOUND)
  enable_testing()
  add_executable(test_suite ${HELIUM_TEST_FILES})
  add_dependencies(test_suite helium)
  target_include_directories(test_suite PUBLIC ${SAMPLE_INCLUDES})
  target_link_libraries(test_suite PUBLIC ${TEST_LIBRARIES})
  add_test(test_on_and_off test_suite)
endif(CUNIT_FOUND)

find_package(Doxygen)
if (DOXYGEN_FOUND)
  configure_file(${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile.out @ONLY)
  add_custom_target(doc ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile.out WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include
    COMMENT "Generating API documentation with Doxygen" )
endif(DOXYGEN_FOUND)

