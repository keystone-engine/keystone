include_directories("../../include")

file(GLOB files "fuzz*.c")
foreach(file ${files})
  get_filename_component(FUZZ_TARGET ${file} NAME_WE)
  add_executable(${FUZZ_TARGET} onefile.c ${FUZZ_TARGET}.c)
  target_link_libraries(${FUZZ_TARGET} keystone)
endforeach()
