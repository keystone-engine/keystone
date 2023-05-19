# CMakeLists.txt for Keystone linking.

file(GLOB_RECURSE src_MC "../lib/MC/*.cpp")
file(GLOB src_Support "../lib/Support/*.c*")
file(GLOB src_Target "../lib/Target/*.cpp")

set(src_core
  ${src_MC}
  ${src_Support}
  ${src_Target}
)

file(GLOB_RECURSE src_AArch64 "../lib/Target/AArch64/*.cpp")
file(GLOB_RECURSE src_ARM "../lib/Target/ARM/*.cpp")
file(GLOB_RECURSE src_Hexagon "../lib/Target/Hexagon/*.cpp")
file(GLOB_RECURSE src_Mips "../lib/Target/Mips/*.cpp")
file(GLOB_RECURSE src_PowerPC "../lib/Target/PowerPC/*.cpp")
file(GLOB_RECURSE src_Sparc "../lib/Target/Sparc/*.cpp")
file(GLOB_RECURSE src_SystemZ "../lib/Target/SystemZ/*.cpp")
file(GLOB_RECURSE src_X86 "../lib/Target/X86/*.cpp")
file(GLOB_RECURSE src_RISCV "../lib/Target/RISCV/*.cpp")

set(src_all ${src_core})

foreach(t ${LLVM_TARGETS_TO_BUILD})
    set(src_all ${src_all} ${src_${t}})
endforeach(t)

include_directories(
  "../../include"
  "../lib/Target/AArch64"
  "../lib/Target/ARM"
  "../lib/Target/Hexagon"
  "../lib/Target/Mips"
  "../lib/Target/PowerPC"
  "../lib/Target/Sparc"
  "../lib/Target/SystemZ"
  "../lib/Target/X86"
  "../lib/Target/RISCV"
)

add_library(keystone
  ${src_all}
  ks.cpp
  EVMMapping.cpp
)

install(TARGETS keystone DESTINATION lib${LLVM_LIBDIR_SUFFIX})

set_target_properties(
  keystone
  PROPERTIES
  archive_output_directory ${CMAKE_CURRENT_BINARY_DIR}/lib
  COMPILER_FLAGS "/EHsc"
  SOVERSION ${KEYSTONE_VERSION_MAJOR}
)

if(NOT BUILD_SHARED_LIBS)
  target_compile_definitions(
    keystone
    PUBLIC
    KEYSTONE_STATIC
  )
endif()

if (APPLE)
  set_target_properties(keystone
                        PROPERTIES
                        INSTALL_RPATH "")
endif()

