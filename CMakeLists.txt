# Keystone Assembler Engine (www.keystone-engine.org)
# By Nguyen Anh Quynh, 2016
# By Amaan Qureshi <amaanq12@gmail.com>, 2025

cmake_minimum_required(VERSION 3.22)
project(keystone VERSION 2.0.0 LANGUAGES C CXX)

# Build options
option(KEYSTONE_BUILD_STATIC_RUNTIME "Embed static runtime" ON)
option(BUILD_LIBS_ONLY "Only build keystone library" OFF)
option(KEYSTONE_BUILD_SHARED_LIBS "Build shared libraries" ON)

# Set default build type if not specified
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(STATUS "No build type selected, default to Release")
  set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
endif()

# Modern CMake policies
if(POLICY CMP0022)
  cmake_policy(SET CMP0022 NEW)
endif()
if(POLICY CMP0048)
  cmake_policy(SET CMP0048 NEW)
endif()
if(POLICY CMP0051)
  cmake_policy(SET CMP0051 NEW) # Updated to use NEW behavior for generator expressions
endif()
if(POLICY CMP0063)
  cmake_policy(SET CMP0063 NEW)
endif()
if(POLICY CMP0074)
  cmake_policy(SET CMP0074 NEW) # Use <PackageName>_ROOT variables
endif()
if(POLICY CMP0077)
  cmake_policy(SET CMP0077 NEW) # Option command respects normal variables
endif()
if(POLICY CMP0135)
  cmake_policy(SET CMP0135 NEW) # Download extract timestamp
endif()
if(POLICY CMP0144)
  cmake_policy(SET CMP0144 NEW) # Use find_package(CUDA) rather than find_package(CUDAToolkit)
endif()

# Set C++ standard to C++17 which is required for LLVM 20
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Handle build type specific flags
string(TOUPPER "${CMAKE_BUILD_TYPE}" uppercase_CMAKE_BUILD_TYPE)
if(uppercase_CMAKE_BUILD_TYPE STREQUAL "DEBUG")
  add_definitions(-DDEBUG)
else()
  add_definitions(-DNDEBUG)
endif()

# Force static build for all LLVM libraries
set(BUILD_SHARED_LIBS OFF)

# Disable building individual LLVM libraries - we'll bundle everything into keystone
set(LLVM_BUILD_STATIC_LIBS OFF)
set(LLVM_BUILD_UTILS OFF)
set(LLVM_BUILD_TOOLS OFF)
set(LLVM_INCLUDE_TOOLS OFF)
set(LLVM_INCLUDE_TESTS OFF)
set(LLVM_INCLUDE_EXAMPLES OFF)
set(LLVM_INCLUDE_DOCS OFF)
set(LLVM_ENABLE_PROJECTS "" CACHE STRING "List of LLVM subprojects to build" FORCE)
set(LLVM_ENABLE_LIBPFM OFF)

# Compiler-specific settings
if(MSVC)
  add_compile_options(/EHsc /W3)
  add_definitions(-D_CRT_SECURE_NO_WARNINGS)

  # Static runtime settings for MSVC
  if(KEYSTONE_BUILD_STATIC_RUNTIME)
    foreach(flag_var
        CMAKE_C_FLAGS CMAKE_C_FLAGS_DEBUG CMAKE_C_FLAGS_RELEASE
        CMAKE_C_FLAGS_MINSIZEREL CMAKE_C_FLAGS_RELWITHDEBINFO
        CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE
        CMAKE_CXX_FLAGS_MINSIZEREL CMAKE_CXX_FLAGS_RELWITHDEBINFO)
      if(${flag_var} MATCHES "/MD")
        string(REGEX REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}")
      endif()
    endforeach()
  endif()
else()
  add_compile_options(-Werror=uninitialized
    "$<$<COMPILE_LANG_AND_ID:C,Clang,AppleClang>:-Werror=sometimes-uninitialized>"
    "$<$<COMPILE_LANG_AND_ID:CXX,Clang,AppleClang>:-Werror=sometimes-uninitialized>"
    -Werror=return-type)

  # Use GNUInstallDirs properly for non-Windows platforms
  include(GNUInstallDirs)

  # Get library directory suffix
  if(CMAKE_INSTALL_LIBDIR MATCHES "lib64")
    set(LLVM_LIBDIR_SUFFIX "64")
  elseif(CMAKE_INSTALL_LIBDIR MATCHES "lib32")
    set(LLVM_LIBDIR_SUFFIX "32")
  else()
    set(LLVM_LIBDIR_SUFFIX "")
  endif()

  # Add LTO support if desired
  option(KEYSTONE_ENABLE_LTO "Enable Link Time Optimization" OFF)
  if(KEYSTONE_ENABLE_LTO)
    include(CheckIPOSupported)
    check_ipo_supported(RESULT IPO_SUPPORTED)
    if(IPO_SUPPORTED)
      set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
    else()
      message(WARNING "LTO requested but not supported by the compiler")
    endif()
  endif()
endif()

set(KEYSTONE_ARCH "aarch64;amdgpu;arm;avr;bpf;csky;evm;hexagon;lanai;loongarch;m68k;mips;msp430;ppc;riscv;sparc;systemz;ve;wasm;x86;xtensa" CACHE STRING "Enabled Keystone architectures")

set(LLVM_TARGETS_TO_BUILD "")

foreach(ARCH ${KEYSTONE_ARCH})
  string(TOUPPER "${ARCH}" ARCH_UPPER)
  set(KEYSTONE_HAS_${ARCH_UPPER} TRUE)

  # Map to LLVM architecture name
  if(ARCH STREQUAL "aarch64")
    list(APPEND LLVM_TARGETS_TO_BUILD "AArch64")
  elseif(ARCH STREQUAL "amdgpu")
    list(APPEND LLVM_TARGETS_TO_BUILD "AMDGPU")
  elseif(ARCH STREQUAL "arm")
    list(APPEND LLVM_TARGETS_TO_BUILD "ARM")
  elseif(ARCH STREQUAL "avr")
    list(APPEND LLVM_TARGETS_TO_BUILD "AVR")
  elseif(ARCH STREQUAL "bpf")
    list(APPEND LLVM_TARGETS_TO_BUILD "BPF")
  elseif(ARCH STREQUAL "csky")
    list(APPEND LLVM_TARGETS_TO_BUILD "CSKY")
  elseif(ARCH STREQUAL "evm")
    # no-op
  elseif(ARCH STREQUAL "hexagon")
    list(APPEND LLVM_TARGETS_TO_BUILD "Hexagon")
  elseif(ARCH STREQUAL "lanai")
    list(APPEND LLVM_TARGETS_TO_BUILD "Lanai")
  elseif(ARCH STREQUAL "loongarch")
    list(APPEND LLVM_TARGETS_TO_BUILD "LoongArch")
  elseif(ARCH STREQUAL "m68k")
    list(APPEND LLVM_TARGETS_TO_BUILD "M68k")
  elseif(ARCH STREQUAL "mips")
    list(APPEND LLVM_TARGETS_TO_BUILD "Mips")
  elseif(ARCH STREQUAL "msp430")
    list(APPEND LLVM_TARGETS_TO_BUILD "MSP430")
  elseif(ARCH STREQUAL "ppc")
    list(APPEND LLVM_TARGETS_TO_BUILD "PowerPC")
  elseif(ARCH STREQUAL "riscv")
    list(APPEND LLVM_TARGETS_TO_BUILD "RISCV")
  elseif(ARCH STREQUAL "sparc")
    list(APPEND LLVM_TARGETS_TO_BUILD "Sparc")
  elseif(ARCH STREQUAL "systemz")
    list(APPEND LLVM_TARGETS_TO_BUILD "SystemZ")
  elseif(ARCH STREQUAL "ve")
    list(APPEND LLVM_TARGETS_TO_BUILD "VE")
  elseif(ARCH STREQUAL "wasm")
    list(APPEND LLVM_TARGETS_TO_BUILD "WebAssembly")
  elseif(ARCH STREQUAL "x86")
    list(APPEND LLVM_TARGETS_TO_BUILD "X86")
  elseif(ARCH STREQUAL "xtensa")
    list(APPEND LLVM_TARGETS_TO_BUILD "Xtensa")
  else()
    message(WARNING "Unknown architecture ${ARCH} specified. Skipping.")
  endif()
endforeach()

set(LLVM_TARGETS_TO_BUILD ${LLVM_TARGETS_TO_BUILD} CACHE STRING "LLVM Targets to Build" FORCE)

# Also add individual architecture definitions for Keystone
foreach(ARCH ${KEYSTONE_ARCH})
  string(TOUPPER "${ARCH}" ARCH_UPPER)
  add_definitions(-DKEYSTONE_HAS_${ARCH_UPPER})
endforeach()

# Add include directories
# When this CMakeLists.txt is the root project, CMAKE_CURRENT_SOURCE_DIR == CMAKE_SOURCE_DIR
# When it's added as a subdirectory (e.g. when building the Python bindings),
# CMAKE_CURRENT_SOURCE_DIR points to the keystone root
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_BINARY_DIR}/llvm/include
)

# Disable installation of LLVM libraries - we only want keystone itself
set(LLVM_INSTALL_LIBRARY_DIR "NOTINSTALLED" CACHE PATH "Installation directory for LLVM libraries" FORCE)
set(LLVM_INSTALL_TOOLCHAIN_ONLY ON CACHE BOOL "Only install toolchain files" FORCE)

# Add LLVM subdirectory with custom configuration
add_subdirectory(llvm)

get_property(KEYSTONE_LLVM_LIBS GLOBAL PROPERTY LLVM_COMPONENT_LIBS)
target_precompile_headers(LLVMMC PRIVATE
  $<$<COMPILE_LANGUAGE:CXX>:${CMAKE_CURRENT_SOURCE_DIR}/llvm/keystone/pch.h>)
foreach(lib ${KEYSTONE_LLVM_LIBS})
  if(NOT lib MATCHES "^LLVM(MC|Support|TargetParser)$")
    target_precompile_headers(${lib} REUSE_FROM LLVMMC)
  endif()
endforeach()

# Generate and install pkg-config file
find_package(PkgConfig)

set(PC_PREFIX "${CMAKE_INSTALL_PREFIX}")
set(PC_LIBDIR "${CMAKE_INSTALL_FULL_LIBDIR}")
set(PC_INCLUDEDIR "${CMAKE_INSTALL_FULL_INCLUDEDIR}")
set(PC_VERSION "${PROJECT_VERSION}")

configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/pkg-config.pc.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.pc"
  @ONLY
)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.pc"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")

# Uninstall target
if(NOT BUILD_LIBS_ONLY)
  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/CMakeUninstall.in"
    "${CMAKE_CURRENT_BINARY_DIR}/CMakeUninstall.cmake"
    @ONLY
  )
  add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/CMakeUninstall.cmake
  )
endif()

include(CMakePackageConfigHelpers)
write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion
)

message(STATUS "Keystone configuration:")
message(STATUS "  Architectures: ${KEYSTONE_ARCH}")
message(STATUS "  Shared libs: ${KEYSTONE_BUILD_SHARED_LIBS}")
message(STATUS "  Static runtime: ${KEYSTONE_BUILD_STATIC_RUNTIME}")
