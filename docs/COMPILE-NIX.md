This documentation explains how to build & install Keystone on all kind of nix OS.
For Windows, see [COMPILE-WINDOWS.md](COMPILE-WINDOWS.md)


1. Dependency

  CMake is required to build keystone.

  - On Mac OS X, you can install "cmake" with "brew".

        $ brew install cmake

  - On Ubuntu Linux, install "cmake" with:

        $ sudo apt-get install cmake


2. From the root directory of Keystone source, compile its dynamic library
   with the following commands.

        $ mkdir build
        $ cd build
        $ ../make-share.sh

   In the case you want to compile with all the debug information, replace the
   last line with:

        $ ../make-share.sh debug

   For Linux distributions following the "Filesystem Hierarchy Standard" and
   put x64 libraries under $PREFIX/lib64, such as Fedora, Redhat & Suse,
   add "fhs" option at the end of make-share.sh script, like below.

        $ ../make-share.sh fhs

   By default, this builds all architectures, which is: AArch64, ARM, Hexagon,
   Mips, PowerPC, Sparc, SystemZ & X86. To compile just some selected ones,
   pass a semicolon-separated list of targets to LLVM_TARGETS_TO_BUILD,
   like follows if we only want AArch64 & X86.

        $ cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DLLVM_TARGETS_TO_BUILD="AArch64, X86" -G "Unix Makefiles" ..
        $ make -j8

   You can also compile static a library with:

        $ mkdir build
        $ cd build
        $ ../make-lib.sh

   In the case you want to compile with all the debug information, replace the
   last line with:

        $ ../make-lib.sh debug

   For Linux distributions following the "Filesystem Hierarchy Standard" and
   put x64 libraries under $PREFIX/lib64, such as Fedora, Redhat & Suse,
   add "fhs" option at the end of make-share.sh script, like below.

        $ ../make-lib.sh fhs

   Like above, this builds all architectures. To compile just some selected ones,
   pass a semicolon-separated list of targets to LLVM_TARGETS_TO_BUILD,
   like follows if we only want AArch64 & X86.

        $ cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DLLVM_TARGETS_TO_BUILD="AArch64, X86" -G "Unix Makefiles" ..
        $ make -j8

   To customize your build by specifying PREFIX or other installation directories,
   pass one of the variables at https://cmake.org/cmake/help/v3.0/module/GNUInstallDirs.html
   to cmake. For example:

        $ cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DLLVM_TARGETS_TO_BUILD="AArch64, X86" -G "Unix Makefiles" ..
        $ make -j8


3. Right after building, install Keystone.

        $ sudo make install

   Keystone is installed in '/usr/local', depending on your distribution (eg. Ubuntu) you might
   need to add '/usr/local/lib' to '/etc/ld.so.conf'. Then update the dynamic linker
   with:
        
        $ sudo ldconfig
   
   Besides the libraries & C header files under  thedirectory "include/keystone",
   this step also installs a tool named "kstool" on the system.
   (The source of "kstool" is in the directory "kstool/kstool")


4. Test Keystone with "kstool" like below.

        $ kstool x32 "add eax, ebx"

   Run "kstool" without any option to find out how to use this handy tool.


5. Learn more on how to code your own tools with our samples.

   For C sample code, see code in directory samples/

   For Python sample code, see code in directory bindings/python/
