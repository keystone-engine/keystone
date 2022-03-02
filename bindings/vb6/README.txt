
Keystone Assembly Engine bindings for VB6
Contributed by FireEye FLARE Team
Author:  David Zimmer <david.zimmer@fireeye.com>, <dzzie@yahoo.com>
License: Apache 2.0
Copyright: FireEye 2017

NOTE: the VB code was built and tested against the latest binary release: Keystone 0.9.1
      I will enabled the symbol resolver once it makes it into the stable release

This is a sample for using the Keystone assembly engine with VB6.

The vbKeystone.dll is written in C. Project files are provided for VS2008.
It is a small shim to give VB6 access to a stdcall API to access keystone.
You could also modify keystone itself so its exports were stdcall.

The C project has an additional include directory set to ./../../include/
for <keystone.h>. This is for the /keystone/bindings/vb6/ directory structure








