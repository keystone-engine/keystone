include(LLVM-Build)

# `Demangle', `Support' and `TargetParser' libraries are added on the top-level
# CMakeLists.txt

add_subdirectory(MC)
add_subdirectory(Target)
add_subdirectory(TargetParser)

set(LLVMCONFIGLIBRARYDEPENDENCIESINC "${LLVM_BINARY_DIR}/tools/llvm-config/LibraryDependencies.inc")

# Special components which don't have any source attached but aggregate other
# components
add_llvm_component_group(all-targets LINK_COMPONENTS ${LLVM_TARGETS_TO_BUILD})
add_llvm_component_group(Engine)

# The native target may not be enabled when cross compiling
if(TARGET ${LLVM_NATIVE_ARCH})
  add_llvm_component_group(Native LINK_COMPONENTS ${LLVM_NATIVE_ARCH})
  add_llvm_component_group(NativeCodeGen LINK_COMPONENTS ${LLVM_NATIVE_ARCH}CodeGen)
else()
  add_llvm_component_group(Native)
  add_llvm_component_group(NativeCodeGen)
endif()

# Component post-processing
LLVMBuildResolveComponentsLink()
LLVMBuildGenerateCFragment(OUTPUT ${LLVMCONFIGLIBRARYDEPENDENCIESINC})
