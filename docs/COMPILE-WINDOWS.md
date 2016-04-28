This documentation explains how to build Keystone on Windows.
For *nix OS, see [COMPILE-NIX.md](COMPILE-NIX.md)


0. Dependency

CMake is required as dependency.
Download & install cmake from http://www.cmake.org

Microsoft Visual Studio is required for compiling. Download & install it from 
https://www.visualstudio.com


1. Open the Visual Studio Command Promplt, and from the root directory
  of Keystone source, do:

    $ mkdir build
    $ cd build

  To build DLL file, run:

    $ ..\nmake-dll.bat

  To build LIB file, run:

    $ ..\nmake-lib.bat

  Find the generated libraries in build\llvm\lib\keystone.{dll,lib}
  
  In the case you build LIB file, a tool named "kstool.exe" is also
  compiled & available under directory "build\kstool".
  (Find source of "kstool" in directory "kstool/kstool")


2. Test Keystone with "kstool" like below.

    > kstool x32 "add eax, ebx"

  Run "kstool" without any option to find out how to use this handy tool.


3. Learn more on how to code your own tools with our samples.

   For C sample code, see code in directory samples/

   For Python sample code, see code in directory bindings/python/
