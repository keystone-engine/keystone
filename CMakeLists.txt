# Keystone Assembler Engine (www.keystone-engine.org)
# By Nguyen Anh Quynh, 2016

cmake_minimum_required(VERSION 2.8.7)
project(keystone)

set(KEYSTONE_VERSION_MAJOR 0)
set(KEYSTONE_VERSION_MINOR 9)

option(KEYSTONE_BUILD_STATIC_RUNTIME "Embed static runtime" ON)
option(BUILD_LIBS_ONLY "Only build keystone library" 0)

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

if (POLICY CMP0063)
  set(CMAKE_POLICY_DEFAULT_CMP0063 NEW) # automatic when 3.3.2 is required
endif()

if (CMAKE_VERSION VERSION_LESS 3.1.20141117)
  set(cmake_3_2_USES_TERMINAL)
else()
  set(cmake_3_2_USES_TERMINAL USES_TERMINAL)
endif()

if (${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /EHsc")
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /EHsc")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /EHsc")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /EHsc")
else()
    set(CMAKE_C_VISIBILITY_PRESET hidden)
    set(CMAKE_CXX_VISIBILITY_PRESET hidden)

    # Use GNUInstallDirs to set LLVM_LIBDIR_SUFFIX. This should automatically
    # handle cases where the libdir should be lib/, lib64/, or lib/<arch>/
    # depending on the target system and cmake options.
    include(GNUInstallDirs)
    string(REGEX REPLACE "lib(.*)$" "\\1" LLVM_LIBDIR_SUFFIX "${CMAKE_INSTALL_LIBDIR}")
    set(LLVM_LIBDIR_SUFFIX "${LLVM_LIBDIR_SUFFIX}" CACHE STRING "Define suffix of library directory name (32/64)")
endif()

# Force static runtime libraries
if (KEYSTONE_BUILD_STATIC_RUNTIME)
    FOREACH(flag
        CMAKE_C_FLAGS_RELEASE CMAKE_C_FLAGS_RELWITHDEBINFO
        CMAKE_C_FLAGS_DEBUG CMAKE_C_FLAGS_DEBUG_INIT
        CMAKE_CXX_FLAGS_RELEASE  CMAKE_CXX_FLAGS_RELWITHDEBINFO
        CMAKE_CXX_FLAGS_DEBUG  CMAKE_CXX_FLAGS_DEBUG_INIT)
        if (MSVC)
            STRING(REPLACE "/MD"  "/MT" "${flag}" "${${flag}}")
            SET("${flag}" "${${flag}} /EHsc")
        endif (MSVC)
    ENDFOREACH()
endif ()

add_subdirectory(llvm)

# for Windows, do not build kstool if buiding DLL
# TODO: fix this
if (${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
if (NOT BUILD_LIBS_ONLY AND NOT BUILD_SHARED_LIBS)
    add_subdirectory(kstool)
endif()
else()
if (NOT BUILD_LIBS_ONLY)
    add_subdirectory(kstool)
endif()
endif()

# generate and install pkg-config.pc
FIND_PACKAGE(PkgConfig)
SET(PKG_CONFIG_FILE_PATH
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.pc"
)
SET(PKG_CONFIG_LIBDIR
    "${CMAKE_INSTALL_PREFIX}/lib${LLVM_LIBDIR_SUFFIX}"
)
SET(PKG_CONFIG_INCLUDEDIR
    "${CMAKE_INSTALL_PREFIX}/include"
)
SET(PKG_CONFIG_LIBS
    "-L\${libdir} -lkeystone"
)
SET(PKG_CONFIG_CFLAGS
    "-I\${includedir}"
)
CONFIGURE_FILE(
    "${CMAKE_CURRENT_SOURCE_DIR}/pkg-config.pc.cmake"
    "${PKG_CONFIG_FILE_PATH}"
)
INSTALL(FILES "${PKG_CONFIG_FILE_PATH}"
        DESTINATION lib${LLVM_LIBDIR_SUFFIX}/pkgconfig)

# uninstall target
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/CMakeUninstall.in"
    "${CMAKE_CURRENT_BINARY_DIR}/CMakeUninstall.cmake"
    IMMEDIATE @ONLY)

if(NOT BUILD_LIBS_ONLY)
    add_custom_target(uninstall
        COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/CMakeUninstall.cmake)
endif()

if(NOT BUILD_LIBS_ONLY)
    add_subdirectory(suite/fuzz)
endif()
