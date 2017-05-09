:: Keystone assembler engine (www.keystone-engine.org)
:: Build Keystone DLL (keystone.dll) for X86, on Windows with CMake & Nmake
:: By Nguyen Anh Quynh, 2017

cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DLLVM_TARGETS_TO_BUILD="X86" -G "NMake Makefiles" ..
nmake

