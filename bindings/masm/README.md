# Keystone bindings for assembler

This documentation explains how to install & use assembler x86/x64 bindings for Keystone.

The `Keystone_x86.inc` file and the `Keystone_x64.inc` files contain the exports, constants and structures required for using Keystone with assembly language.

These files are a conversion of the original files: `keystone.h`, & `x86.h` to a format that will work with x86 assemblers (MASM) and x64 assemblers (UASM)


## Keystone DLLs

* Compile the relevant version (x86/x64) of `keystone.dll`
* (Optional) Rename the x86 version of `keystone.dll` to `keystone_x86.dll`, and the x64 version of `keystone.dll` to `keystone_x64.dll` - depending on which versions you might be linking with in your projects.
* Copy the `keystone.dll` (or `keystone_x86.dll` / `keystone_x64.dll`) to your assembly projects folder or a `%PATH%` folder.

Alternatively, static libraries and pre-compiled DLL’s can be obtained from the Keystone homepage
at http://keystone-engine.org/download. Select the appropriate package to download under the Windows Core engine section: Win-32 and/or Win-64


## Keystone Stub Libraries for DLLs

To create the stub libraries for use with Keystone use the following commands (may differ depending on your installation of visual studio):

To create the keystone stub library file (`keystone_x86.lib`) for MASM x86 Assembler:
* Open the VS2013 x86 Native Tools Command Prompt 
* Navigate to the `Keystone\bindings\masm` folder
* Run the following command `lib /DEF:keystone.def /OUT:keystone_x86.lib /MACHINE:X86`

To create the keystone stub library file (`keystone_x64.lib`) for UASM x64 Assembler:
* Open the VS2013 x64 Native Tools Command Prompt
* Navigate to the `Keystone\bindings\masm` folder
* Run the following command `lib /DEF:keystone.def /OUT:keystone_x64.lib /MACHINE:X64`

The usage sections below assume you created the keystone stub libraries for the appropriate x86/x64 DLL


## MASM32 x86 Assembler Usage

* Copy the `Keystone_x86.inc` file from the `Keystone\bindings\masm` folder to your `masm32\include` folder
* Copy the `keystone_x86.lib` file from the `Keystone\bindings\masm` folder to your `masm32\lib` folder
* Copy the `keystone_x86.dll` file (or x86 version of `keystone.dll`) to your assembly projects folder.
* Add the following lines to your source code:
```
    include Keystone_x86.inc
    includelib keystone_x86.lib
```


## UASM x64 Assembler Usage

* Copy the `Keystone_x64.inc` file from the `Keystone\bindings\masm` folder to your `UASM\include` folder
* Copy the `Keystone_x64.lib` file from the `Keystone\bindings\masm` folder to your `UASM\lib` folder
* Copy the `keystone_x64.dll` file (or x64 version of `keystone.dll`) to your assembly projects folder.
* Add the following lines to your source code:
```
    include Keystone_x64.inc
    includelib Keystone_x64.lib
```


## RadASM Auto-complete files for MASM & UASM (Optional)

Additional files are included for use with RadASM's auto-complete / intelliSense feature. These text files  incorporate the keystone api calls and defined constants for api call parameters - for ease of use.

* `masmApiCall.api.txt` - _RadASM code completion file for api calls (for MASM x86)_
* `masmApiConst.api.txt` - _RadASM code completion file for constants (for MASM x86)_

Basic installation instructions:

* Open each .txt file listed above (for the assembler you will be using with RadASM)
* Copy the contents of the .txt file, and paste into the matching .api file

Instructions are included in the text files themselves as to which file it is related to and the typical location of those .api files.


## Examples

Included are two keystone example RadASM projects, for MASM x86 and UASM x64 assemblers:
* `KSExample_x86`
* `KSExample_x64`


## Resources

* [MASM32](http://www.masm32.com/masmdl.htm)
* [UASM](http://www.terraspace.co.uk/uasm.html)
