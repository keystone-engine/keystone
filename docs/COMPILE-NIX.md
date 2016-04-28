This documentation explains how to build & install Keystone on all kind of nix OS.
For Windows, see [COMPILE-WINDOWS.md](COMPILE-WINDOWS.md)


0. Dependency

CMake is required as dependency.

- On Mac OS X, you can install "cmake" with "brew".

        $ brew install cmake

- On Utunbu Linux, install "cmake" with.

        $ sudo apt-get install cmake


1. From the root directory of Keystone source, compile dynamic library
   with below commands.

        $ mkdir build
        $ cd build
        $ ../make-share.sh

   You can also compile static libray with.

        $ mkdir build
        $ cd build
        $ ../make-lib.sh


2. Right after building step, install Keystone.

        $ sudo make install

   Besides the libraries & C header files under directory "include/keystone",
   this step also installs a tool named "kstool" into the system.
   (Find source of "kstool" in directory "kstool/kstool")


3. Test Keystone with "kstool" like below.

        $ kstool x32 "add eax, ebx"

   Run "kstool" without any option to find out how to use this handy tool.


4. Learn more on how to code your own tools with our samples.

   For C sample code, see code in directory samples/

   For Python sample code, see code in directory bindings/python/
