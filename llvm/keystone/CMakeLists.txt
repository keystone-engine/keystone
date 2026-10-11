set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

set(EVM_SOURCES)
if(KEYSTONE_HAS_EVM)
  list(APPEND EVM_SOURCES evm.cpp)
endif()

# Simplified approach - link with LLVM libraries but clean up outputs later
set(KEYSTONE_LINK_LIBS LLVMMC LLVMMCParser LLVMTargetParser LLVMSupport)

foreach(
  ARCH_CONFIG
  AARCH64:AArch64
  AMDGPU:AMDGPU
  ARM:ARM
  AVR:AVR
  BPF:BPF
  CSKY:CSKY
  HEXAGON:Hexagon
  LANAI:Lanai
  LOONGARCH:LoongArch
  M68K:M68k
  MIPS:Mips
  MSP430:MSP430
  PPC:PowerPC
  RISCV:RISCV
  SPARC:Sparc
  SYSTEMZ:SystemZ
  VE:VE
  WASM:WebAssembly
  X86:X86
  XTENSA:Xtensa
)
  string(REPLACE ":" ";" ARCH_PAIR ${ARCH_CONFIG})
  list(GET ARCH_PAIR 0 KS_ARCH)
  list(GET ARCH_PAIR 1 LLVM_ARCH)

  if(KEYSTONE_HAS_${KS_ARCH})
    list(APPEND KEYSTONE_LINK_LIBS LLVM${LLVM_ARCH}AsmParser LLVM${LLVM_ARCH}Desc LLVM${LLVM_ARCH}Info)

    # Add utils libraries if they exist for specific architectures
    if(LLVM_ARCH STREQUAL "AArch64" OR LLVM_ARCH STREQUAL "ARM" OR LLVM_ARCH STREQUAL "AMDGPU")
      list(APPEND KEYSTONE_LINK_LIBS LLVM${LLVM_ARCH}Utils)
    endif()
  endif()
endforeach()

# Shared library
add_library(keystone SHARED ks.cpp ${EVM_SOURCES})

# Exported symbols are GC roots, so export only the C API.
if(APPLE)
  target_link_options(keystone PRIVATE -Wl,-dead_strip "-Wl,-exported_symbol,_ks_*")
elseif(UNIX)
  file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/keystone.map "{ global: ks_*; local: *; };\n")
  target_link_options(keystone PRIVATE -Wl,--gc-sections
    -Wl,--version-script=${CMAKE_CURRENT_BINARY_DIR}/keystone.map)
endif()

# Static library  
add_library(keystone_static STATIC ks.cpp ${EVM_SOURCES})

get_filename_component(KEYSTONE_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../.. ABSOLUTE)

# Set up include directories for both libraries
set(KEYSTONE_INCLUDE_DIRS
  ${KEYSTONE_ROOT_DIR}/include 
  ${KEYSTONE_ROOT_DIR}/llvm/include
  ${CMAKE_BINARY_DIR}/llvm/include
)

target_include_directories(keystone PRIVATE ${KEYSTONE_INCLUDE_DIRS})
target_include_directories(keystone INTERFACE ${KEYSTONE_ROOT_DIR}/include)

target_include_directories(keystone_static PRIVATE ${KEYSTONE_INCLUDE_DIRS})
target_include_directories(keystone_static INTERFACE ${KEYSTONE_ROOT_DIR}/include)

# Link with LLVM component libraries
target_link_libraries(keystone ${KEYSTONE_LINK_LIBS})
target_link_libraries(keystone_static ${KEYSTONE_LINK_LIBS})

# Also link system libraries
if(UNIX AND NOT APPLE)
  target_link_libraries(keystone m pthread dl)
  target_link_libraries(keystone_static m pthread dl)
elseif(APPLE)
  target_link_libraries(keystone m pthread)
  target_link_libraries(keystone_static m pthread)
endif()

# Create combined static library that includes all LLVM libraries
set(COMBINED_LIB_PATH ${CMAKE_BINARY_DIR}/libkeystone.a)

if(UNIX)
  # Create an MRI script to combine all libraries
  set(MRI_SCRIPT_CONTENT "CREATE ${COMBINED_LIB_PATH}
ADDLIB $<TARGET_FILE:keystone_static>")
  
  foreach(lib ${KEYSTONE_LINK_LIBS})
    string(APPEND MRI_SCRIPT_CONTENT "
ADDLIB $<TARGET_FILE:${lib}>")
  endforeach()
  
  string(APPEND MRI_SCRIPT_CONTENT "
SAVE
END
")

  # Generate the script file
  file(
    GENERATE
    OUTPUT ${CMAKE_BINARY_DIR}/combine_libs.mri
    CONTENT "${MRI_SCRIPT_CONTENT}")

  add_custom_command(
    OUTPUT ${COMBINED_LIB_PATH}
    COMMAND ${CMAKE_AR} -M < ${CMAKE_BINARY_DIR}/combine_libs.mri
    DEPENDS keystone_static ${KEYSTONE_LINK_LIBS}
    COMMENT "Creating combined static library"
    VERBATIM)

  # Create a target for the combined library
  add_custom_target(keystone_combined ALL DEPENDS ${COMBINED_LIB_PATH})
  add_dependencies(keystone_combined keystone_static ${KEYSTONE_LINK_LIBS})

  # Custom target to clean up intermediate libraries after build
  add_custom_target(cleanup_intermediate_libs
    COMMAND ${CMAKE_COMMAND} -E echo "Cleaning up intermediate LLVM libraries..."
    COMMAND find ${CMAKE_BINARY_DIR} -name "libLLVM*.a" ! -path "*/keystone/*" -delete || true
    DEPENDS keystone_combined
    COMMENT "Removing intermediate LLVM .a files"
    VERBATIM)
endif()

# Install both shared and combined static libraries
install(
  TARGETS keystone
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

# Install the combined static library
if(UNIX)
  install(FILES ${COMBINED_LIB_PATH} DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()

install(FILES ${KEYSTONE_ROOT_DIR}/include/keystone/keystone.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/keystone)
