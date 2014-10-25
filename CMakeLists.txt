cmake_minimum_required(VERSION 3.0)
project(libhelium)
set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake-scripts)

include(CheckIncludeFiles)
include(CheckFunctionExists)

# Build with blocks by default. If you don't have clang it'll whine at you.
option(BLOCKS "BLOCKS" ON)

set(VERSION_MAJOR "0")
set(VERSION_MINOR "0")
set(VERSION_PATCH "1")
set(VERSION "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}")
add_definitions(-DLIBHELIUM_VERSION="${VERSION}")
add_definitions(-D_GNU_SOURCE) # you need this or libuv will not be happy
add_definitions(-DHAVE_CONFIG_H)

find_package(uv)
find_package(openssl)
find_package(crypto)
find_package(cunit)

if(BLOCKS AND NOT APPLE)
  find_package(blocksruntime)
endif(BLOCKS AND NOT APPLE)


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

CHECK_FUNCTION_EXISTS(vsnprintf HAVE_VSNPRINTF)
CHECK_FUNCTION_EXISTS(snprintf HAVE_SNPRINTF)
CHECK_FUNCTION_EXISTS(vasprintf HAVE_VASPRINTF)
CHECK_FUNCTION_EXISTS(asprintf HAVE_ASPRINTF)
CHECK_INCLUDE_FILES("stdarg.h" HAVE_STDARG_H)
CHECK_INCLUDE_FILES("stddef.h" HAVE_STDDEF_H)
CHECK_INCLUDE_FILES("stdint.h" HAVE_STDINT_H)
CHECK_INCLUDE_FILES("stdlib.h" HAVE_STDLIB_H)
CHECK_INCLUDE_FILES("inttypes.h" HAVE_INTTYPES_H)
CHECK_INCLUDE_FILES("locale.h" HAVE_LOCALE_H)
CHECK_FUNCTION_EXISTS(localeconv HAVE_LOCALECONV)
CHECK_FUNCTION_EXISTS(lconv_decimal_point HAVE_LCONV_DECIMAL_POINT)
CHECK_FUNCTION_EXISTS(lconv_thousands_sep HAVE_LCONV_THOUSANDS_SEP)

if((${CMAKE_C_COMPILER_ID} STREQUAL "Clang") OR (${CMAKE_C_COMPILER_ID} STREQUAL "GNU")) 
  set(CMAKE_C_FLAGS "-Wall -pedantic -Werror -std=c90 -funsigned-char -Wno-long-long")
endif((${CMAKE_C_COMPILER_ID} STREQUAL "Clang") OR (${CMAKE_C_COMPILER_ID} STREQUAL "GNU"))

configure_file ("include/config.h.in"
  "include/config.h" )

set(HELIUM_SOURCE_FILES
  src/logging.c
  src/hashmap.c
  src/helium.c
  src/snprintf.c
  include/helium.h
  include/helium_logging.h
  include/helium_internal.h)

set(HELIUM_HEADER_FILES
  include/helium_logging.h
  include/helium.h)

if(CMAKE_C_COMPILER_ID MATCHES "clang")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fblocks -fsanitize=undefined")
  add_definitions(-DHAVE_BLOCKS=1)
else()
  add_definitions(-DHAVE_BLOCKS=0)
endif(CMAKE_C_COMPILER_ID MATCHES "clang")

if(WIN32) 
	include(GenerateExportHeader)
	set(HELIUM_LIBS ${HELIUM_LIBS} ws2_32 psapi iphlpapi)
endif()

if(MSVC)
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /NODEFAULTLIB:LIBCMTD.lib")
	set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /NODEFAULTLIB:LIBCMTD.lib")
endif()

message("HELIUM_INCLUDES are ${HELIUM_INCLUDES}")
message("HELIUM_LIBS ARE ${HELIUM_LIBS}")

add_library(helium SHARED ${HELIUM_SOURCE_FILES})
if(WIN32)
	generate_export_header(helium)
else()
	add_library(heliumStatic STATIC ${HELIUM_SOURCE_FILES})
	set_target_properties(heliumStatic PROPERTIES OUTPUT_NAME helium)
	target_include_directories(heliumStatic PUBLIC ${HELIUM_INCLUDES})
	target_link_libraries(heliumStatic PUBLIC ${HELIUM_LIBS})
endif()
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
  ${OPENSSL_LIBRARIES}
  ${UV_LIBRARIES}
  ${CRYPTO_LIBRARIES})

IF(UNIX)
  set(SAMPLE_LIBRARIES ${SAMPLE_LIBRARIES} m ${CMAKE_CURRENT_BINARY_DIR}/libhelium.a)
ENDIF(UNIX)
if(WIN32)
	set(SAMPLE_LIBRARIES ${SAMPLE_LIBRARIES} Debug/helium)
endif()

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
  add_executable(test_basic tests/test_basic.c)
  add_dependencies(test_basic helium)
  target_include_directories(test_basic PUBLIC ${SAMPLE_INCLUDES})
  target_link_libraries(test_basic PUBLIC ${TEST_LIBRARIES})
  add_test(test_basic test_basic)

  add_executable(test_base64 tests/test_base64.c)
  add_dependencies(test_base64 helium)
  target_include_directories(test_base64 PUBLIC ${SAMPLE_INCLUDES})
  target_link_libraries(test_base64 PUBLIC ${TEST_LIBRARIES})
  add_test(test_base64 test_base64)
endif(CUNIT_FOUND)

find_package(Doxygen)
if (DOXYGEN_FOUND)
  configure_file(${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile.out @ONLY)
  add_custom_target(doc ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile.out WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include
    COMMENT "Generating API documentation with Doxygen" )
endif(DOXYGEN_FOUND)

add_custom_target(uninstall "${CMAKE_COMMAND}" -P "${CMAKE_MODULE_PATH}/uninstall.cmake")
