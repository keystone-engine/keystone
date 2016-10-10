This documentation explains how to use the Keystone project as a library in a cross compiled project. It assumes the use of Mingw GCC suite for compilation.

Cross-compiling for Windows from Linux

0. Dependency
  
To be able to cross-compile from Linux to Windows, you will need the Windows libraries found on the download page of Keystone engine. After download, decompress them and place them in you project path.


1. Dynamic Libraries
  
To use the dynamic libraries of Keystone, just use the following in your GCC command line :

	-I ./<path to>/keystone-0.9.1-winXX/include/	     for the include part
	-L ./<path to>/keystone-0.9.1-winXX/ -lkeystone      for the linking part

where XX is 32 or 64.

To be able to use you compiled application on Windows, ship then the keystone.dll file with your application.


2. Static Libraries
  
To avoid shipping the dll file with your project, you may want to use the Keystone static libraries instead.

2.1. 32 bits architecture

There, you would use the following on your GCC command line :

	-I ./<path to>/keystone-0.9.1-win32/include/	     for the include part
	./<path to>/keystone-0.9.1-winXX/keystone.lib      for the linking part

Your Mingw compiler should be able to understand the .lib file directly (not tested for now).

2.2. 64 bits architecture

Using the 64 bits version of keystone.lib is not recognized by the Mingw compiler. There is so a need in transforming the keystone.lib file into a keystone.a file.

2.2.1. Dependency

gendef and dlltool are required to translate the lib file.

	- On Ubuntu Linux (debian based), install "gendef" with:

			$ sudo apt-get install mingw-w64-tools
  
	- dlltool is normally shipped with your installation of the Mingw compiler (on a 64 bits ubuntu, you will find it as x86_64-w64-mingw32-dlltool). If you don't have it, you can install it :
        		
		$ sudo apt-get install mingw-w64

2.2.2. In the keystone-0.9.1-win64 directory, enter the following commands :

	$ gendef keystone.dll
	$ x86_64-w64-mingw32-dlltool --as-flags=--64 -m i386:x86-64 -k --output-lib libkeystone.a --input-def keystone.def


2.2.3. You now have a standard .a file that can be used in you command to compile by using :

	-I ./<path to>/keystone-0.9.1-win32/include/	     for the include part
    ./<path to>/keystone-0.9.1-winXX/keystone.a      for the linking part
