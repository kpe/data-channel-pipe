# Project
cmake_minimum_required(VERSION 3.2)

project(rawrtc-datachannel-pipe
        VERSION 0.0.1)
set(PROJECT_DESCRIPTION
        "A tool for piping data over a WebRTC DataChannel using the alsome RawRTC WebRTC implementation")

set(PROJECT_URL
        "https://github.com/kpe/rawrtc-datachanel-pipe")

set(VERSION_LIB_RE     "libre >= 0.5.0")
set(VERSION_LIB_RAWRTC "librawrtc >= 0.2.2")

# Debug build type as default
if (NOT CMAKE_BUILD_TYPE)
    message(STATUS "No build type selected, using DEBUG")
    set(CMAKE_BUILD_TYPE "RELEASE")
endif()

# Enable verbose output in DEBUG mode
if (${CMAKE_BUILD_TYPE} MATCHES "DEBUG")
    message(STATUS "enabling verbose outout")
    set(CMAKE_VERBOSE_MAKEFILE on)
endif()

# Use pkg-config
find_package(PkgConfig REQUIRED)

# Dependency list
set(dc_pipe_DEP_LIBRARIES)

# Dependency: libre
pkg_check_modules(LIB_RE REQUIRED ${VERSION_LIB_RE})
include_directories(${LIB_RE_STATIC_INCLUDE_DIRS} ${LIB_RE_STATIC_INCLUDEDIR})
link_directories(${LIB_RE_STATIC_LIBRARY_DIRS})
list(APPEND dc_pipe_DEP_LIBRARIES ${LIB_RE_STATIC_LIBRARIES})

# Dependency: librawrtc
pkg_check_modules(LIB_RAWRTC REQUIRED ${VERSION_LIB_RAWRTC})
include_directories(${LIB_RAWRTC_INCLUDE_DIRS} ${LIB_RAWRTC_STATIC_INCLUDEDIR})
link_directories(${LIB_RAWRTC_LIBRARY_DIRS})
list(APPEND dc_pipe_DEP_LIBRARIES ${LIB_RAWRTC_LIBRARIES})

# Walk through subdirectories
add_subdirectory(src)
