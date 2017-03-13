:: Keystone assembler engine (www.keystone-engine.org)
:: Build Keystone static library (keystone.lib) on Windows with CMake & Nmake
:: By Nguyen Anh Quynh, 2016

:: This generates .\llvm\lib\keystone.lib

cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DLLVM_TARGETS_TO_BUILD="all" -G "NMake Makefiles" ..
nmake

