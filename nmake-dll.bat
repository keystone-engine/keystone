:: Keystone assembler engine (www.keystone-engine.org)
:: Build Keystone DLL (keystone.dll) on Windows with CMake & Nmake
:: By Nguyen Anh Quynh, 2016

:: This generates .\llvm\bin\keystone.dll

cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DLLVM_TARGETS_TO_BUILD="all" -G "NMake Makefiles" ..
nmake

