# Keystone Assembler Engine (www.keystone-engine.org)
# By Nguyen Anh Quynh, 2016

cmake_minimum_required(VERSION 2.8.12.2)

set(KEYSTONE_VERSION_MAJOR 1)
set(KEYSTONE_VERSION_MINOR 0)

if (NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(STATUS "No build type selected, default to Debug")
  set(CMAKE_BUILD_TYPE "Debug")
endif()

if (POLICY CMP0022)
  cmake_policy(SET CMP0022 NEW) # automatic when 2.8.12 is required
endif()

if (POLICY CMP0051)
  # CMake 3.1 and higher include generator expressions of the form
  # $<TARGETLIB:obj> in the SOURCES property.  These need to be
  # stripped everywhere that access the SOURCES property, so we just
  # defer to the OLD behavior of not including generator expressions
  # in the output for now.
  cmake_policy(SET CMP0051 OLD)
endif()

if (CMAKE_VERSION VERSION_LESS 3.1.20141117)
  set(cmake_3_2_USES_TERMINAL)
else()
  set(cmake_3_2_USES_TERMINAL USES_TERMINAL)
endif()

if (${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /EHsc")
endif()

add_subdirectory(llvm)

# for Windows, do not build kstool if buiding DLL
# TODO: fix this
if (${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
if (NOT BUILD_SHARED_LIBS)
    add_subdirectory(kstool)
endif()
else()
    add_subdirectory(kstool)
endif()
