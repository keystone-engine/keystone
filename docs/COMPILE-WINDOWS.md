This documentation explains how to build Keystone on Windows.
For *nix OS, see [COMPILE-NIX.md](COMPILE-NIX.md)


1. Dependency

  CMake is required as dependency.
  Download & install cmake from http://www.cmake.org

  Microsoft Visual Studio 2013 or older is required for compiling.
  Download & install it from https://www.visualstudio.com

  Python is another dependency. Download & install it from
  https://www.python.org


2. Open the Visual Studio Command Promplt, and from the root directory
  of Keystone source, do:

        $ mkdir build
        $ cd build

  To build DLL file, run:

        $ ..\nmake-dll.bat

  By default, this builds all architectures, which is: AArch64, ARM, Hexagon,
  Mips, PowerPC, Sparc, SystemZ & X86. To compile just some selected ones,
  pass a semicolon-separated list of targets to LLVM_TARGETS_TO_BUILD,
  like follows if we only want AArch64 & X86.

        $ cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DLLVM_TARGETS_TO_BUILD="AArch64, X86" -G "NMake Makefiles" ..
        $ nmake

  To build LIB file, run:

        $ ..\nmake-lib.bat

  Like above, this builds all architectures. To compile just some selected ones,
  pass a semicolon-separated list of targets to LLVM_TARGETS_TO_BUILD,
  like follows if we only want AArch64 & X86.

        $ cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DLLVM_TARGETS_TO_BUILD="AArch64, X86" -G "NMake Makefiles" ..
        $ nmake

  Find the generated libraries in build\llvm\lib\keystone.{dll,lib}
  
  In the case you build LIB file, a tool named "kstool.exe" is also
  compiled & available under directory "build\kstool".
  (Find source of "kstool" in directory "kstool/kstool")


3. Test Keystone with "kstool" like below.

        $ kstool.exe x32 "add eax, ebx"

  Run "kstool.exe" without any option to find out how to use this handy tool.


4. Learn more on how to code your own tools with our samples.

   For C sample code, see code in directory samples/

   For Python sample code, see code in directory bindings/python/
