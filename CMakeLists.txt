project(xmr-stak)

cmake_minimum_required(VERSION 2.8)

# enforce C++11
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 11)
if (${CMAKE_MAJOR_VERSION} LESS 3)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
endif()

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX "${CMAKE_BINARY_DIR}" CACHE PATH "install prefix" FORCE)
endif(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)

# allow user to extent CMAKE_PREFIX_PATH via environment variable
list(APPEND CMAKE_PREFIX_PATH "$ENV{CMAKE_PREFIX_PATH}")

enable_testing()
find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

include(cmake/Architecture.cmake)

################################################################################
# CMake user options
################################################################################

set(BUILD_TYPE "Release;Debug")
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Choose the type of build" FORCE)
endif()
set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "${BUILD_TYPE}")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -funroll-all-loops")


# option to add static libgcc and libstdc++
option(CMAKE_LINK_STATIC "link as much as possible libraries static" OFF)

################################################################################
# Find PThreads
################################################################################

find_package(Threads REQUIRED)
set(LIBS ${LIBS} ${CMAKE_THREAD_LIBS_INIT})

################################################################################
# Find microhttpd
################################################################################

option(MICROHTTPD_ENABLE "Enable or disable the requirement of microhttp (http deamon)" ON)
if(MICROHTTPD_ENABLE)
    find_path(MTHD_INCLUDE_DIR
        NAMES
            microhttpd.h
        PATHS
            /opt/local
            /usr/local
            /usr
            ENV "PROGRAMFILES(X86)"
            ENV "HWLOC_ROOT"
        PATH_SUFFIXES
            include)

    find_library(MHTD
        NAMES
            microhttpd
            libmicrohttpd.lib
        PATHS
            ENV "MICROHTTPD_ROOT"
        PATH_SUFFIXES
            lib)
    if("${MHTD}" STREQUAL "MHTD-NOTFOUND")
        message(FATAL_ERROR "microhttpd NOT found: use `-DMICROHTTPD_ENABLE=OFF` to build without http deamon support")
    else()
        set(LIBS ${LIBS} ${MHTD})
        include_directories(AFTER ${MTHD_INCLUDE_DIR})
    endif()
else()
    add_definitions("-DCONF_NO_HTTPD")
endif()

###############################################################################
# Find OpenSSL
###############################################################################

option(OpenSSL_ENABLE "Enable or disable the requirement of OpenSSL" ON)
if(OpenSSL_ENABLE)
    find_package(OpenSSL)
    if(OPENSSL_FOUND)
        include_directories(${OPENSSL_INCLUDE_DIR})
        set(LIBS ${LIBS} ${OPENSSL_LIBRARIES})
    else()
        message(FATAL_ERROR "OpenSSL NOT found: use `-DOpenSSL_ENABLE=OFF` to build without SSL support")
    endif()
else()
    add_definitions("-DCONF_NO_TLS")
endif()

################################################################################
# Find hwloc
################################################################################

option(HWLOC_ENABLE "Enable or disable the requirement of hwloc" ON)
if(HWLOC_ENABLE)
    find_path(HWLOC_INCLUDE_DIR
        NAMES
            hwloc.h
        PATHS
            /opt/local
            /usr/local
            /usr
            ENV "PROGRAMFILES(X86)"
            ENV "HWLOC_ROOT"
        PATH_SUFFIXES
            include)

    find_library(HWLOC
        NAMES
            libhwloc.lib
            hwloc
        PATHS
            ENV "HWLOC_ROOT"
        PATH_SUFFIXES
            lib)

    if("${HWLOC}" STREQUAL "MHTD-NOTFOUND" OR ${HWLOC_INCLUDE_DIR} STREQUAL "HWLOC_INCLUDE_DIR-NOTFOUND")
        message(FATAL_ERROR "hwloc NOT found: use `-DHWLOC_ENABLE=OFF` to build without hwloc support")
    else()
        set(LIBS ${LIBS} ${HWLOC})
        include_directories(AFTER ${HWLOC_INCLUDE_DIR})
    endif()
else()
    add_definitions("-DCONF_NO_HWLOC")
endif()

################################################################################
# Sockets
################################################################################

if(WIN32)
    set(LIBS ${LIBS} wsock32 ws2_32)
endif()
if(CMAKE_SYSTEM_NAME MATCHES SunOS)
    set(LIBS ${LIBS} socket)
endif()

################################################################################
# Compile & Link
################################################################################

# activate static libgcc and libstdc++ linking
if(CMAKE_LINK_STATIC)
    set(BUILD_SHARED_LIBRARIES OFF)
    set(DL_LIB ${CMAKE_DL_LIBS})
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
    set(LIBS "-static-libgcc -static-libstdc++ ${LIBS}")
endif()

include_directories(crypto)
file(GLOB SRCFILES_CPP
  "console.cpp"
  "executor.cpp"
  "httpd.cpp"
  "jconf.cpp"
  "jpsock.cpp"
  "minethd.cpp"
  "socket.cpp"
  "webdesign.cpp"
  "crypto/keccak.cpp" "crypto/cryptonight.cpp" "crypto/groestl.cpp")
file(GLOB SRCFILES_C "crypto/*.c")

include(cmake/Architecture.cmake)

## x86 specific build
if (ARCHITECTURE STREQUAL "x86_64")
  list(APPEND SRCFILES_CPP crypto/cryptonight_aesni.cpp crypto/cryptonight_aesni.hpp)
  set_source_files_properties(crypto/cryptonight_aesni.cpp PROPERTIES COMPILE_FLAGS -maes)
endif()

## Power pc specific build
if (ARCHITECTURE MATCHES ".*ppc.*")
  add_definitions(-mabi=altivec -maltivec)
  list(APPEND SRCFILES_CPP crypto/cryptonight_altivec.cpp crypto/cryptonight_altivec.hpp)
  set_source_files_properties(crypto/cryptonight_altivec.cpp PROPERTIES COMPILE_FLAGS "-mvsx -mcrypto -mtune=native -mcpu=native")
endif()

## Hacks to ensure AIX works
if (ARCHITECTURE MATCHES ".*aix.*")
  add_definitions(-pthread)
  file(GLOB LIBPATH /opt/freeware/lib/gcc/*/*/pthread/ppc64)
  link_directories(${LIBPATH})
endif()

## Sparc specific build
if (ARCHITECTURE STREQUAL "sun4v")
  list(APPEND SRCFILES_CPP crypto/cryptonight_sparc.cpp crypto/cryptonight_sparc.hpp)
  set_source_files_properties(crypto/cryptonight_sparc.cpp PROPERTIES COMPILE_FLAGS "-mtune=native -mcpu=native")
endif()

add_library(xmr-stak-c
    STATIC
    ${SRCFILES_C}
)
set_property(TARGET xmr-stak-c PROPERTY C_STANDARD 99)
target_link_libraries(xmr-stak-c ${LIBS})

add_library(xmr-stak-cpp
  STATIC
  ${SRCFILES_CPP}
)
target_link_libraries(xmr-stak-cpp ${LIBS} xmr-stak-c)

add_executable(xmr-stak
    cli-miner.cpp
)

set(EXECUTABLE_OUTPUT_PATH "bin")
target_link_libraries(xmr-stak ${LIBS} xmr-stak-c xmr-stak-cpp)

add_executable(gtest test/googletest_correct.cpp)
target_link_libraries(gtest ${GTEST_BOTH_LIBRARIES} xmr-stak-cpp xmr-stak-c)

################################################################################
# Install
################################################################################

set(CMAKE_SKIP_RPATH true)
#set(CMAKE_BUILD_WITH_INSTALL_RPATH true)
#set(CMAKE_SKIP_BUILD_RPATH false)
set(CMAKE_INSTALL_RPATH "/usr/gcc/5.5/lib/sparcv9")
#set(CMAKE_INSTALL_RPATH_USE_LINK_PATH true)
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-rpath ${CMAKE_INSTALL_RPATH}")

# do not install the binary if the project and install are equal
if( NOT "${CMAKE_INSTALL_PREFIX}" STREQUAL "${PROJECT_BINARY_DIR}" )
    install(TARGETS xmr-stak
            RUNTIME DESTINATION "${CMAKE_INSTALL_PREFIX}/bin")
    install(TARGETS gtest
            RUNTIME DESTINATION "${CMAKE_INSTALL_PREFIX}/bin")
endif()


# avoid overwrite of user defined settings
# install `config.txt`if file not exists in `${CMAKE_INSTALL_PREFIX}/bin`
if (${CMAKE_MAJOR_VERSION} LESS 3)
  install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/config.txt DESTINATION ${CMAKE_INSTALL_PREFIX}/bin)
else()
  install(CODE " \
    if(NOT EXISTS ${CMAKE_INSTALL_PREFIX}/bin/config.txt)\n   \
        file(INSTALL ${CMAKE_CURRENT_SOURCE_DIR}/config.txt   \
            DESTINATION ${CMAKE_INSTALL_PREFIX}/bin)\n        \
    endif()"
  )
endif()
