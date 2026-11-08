find_package(Python 3.12 REQUIRED COMPONENTS Interpreter Development.SABIModule)

python_add_library(keystone_python MODULE USE_SABI 3.12 WITH_SOABI keystone.c)
set_target_properties(keystone_python PROPERTIES OUTPUT_NAME _keystone)
target_compile_definitions(keystone_python PRIVATE KEYSTONE_VERSION="${PROJECT_VERSION}")
target_link_libraries(keystone_python PRIVATE keystone_static)

if(APPLE)
  target_link_options(keystone_python PRIVATE -Wl,-dead_strip "-Wl,-exported_symbol,_PyInit__keystone")
elseif(UNIX)
  file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/keystone.map "{ global: PyInit__keystone; local: *; };\n")
  target_link_options(keystone_python PRIVATE -Wl,--gc-sections
    -Wl,--version-script=${CMAKE_CURRENT_BINARY_DIR}/keystone.map)
endif()

install(TARGETS keystone_python LIBRARY DESTINATION keystone COMPONENT python)
install(DIRECTORY keystone/ DESTINATION keystone COMPONENT python)
