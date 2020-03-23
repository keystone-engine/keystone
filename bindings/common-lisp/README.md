Common Lisp bindings to the Keystone assembler.

Install using Quicklisp with:
```lisp
(ql:quickload :keystone)
```

The KEYSTONE package provides raw access to the keystone C API from
Common Lisp.  Its usage to drive `ks-disasm` is demonstrated in the
`ks-asm-original-example` test in test.lisp.

The KEYSTONE/CLOS package provides a more lispy interface to Keystone.
For example:

```
KEYSTONE/CLOS> (version)
0
9
KEYSTONE/CLOS> (defparameter engine
                 (make-instance 'keystone-engine :architecture :x86 :mode :32))
ENGINE
KEYSTONE/CLOS> (asm engine "INC ecx; DEC edx")
#(65 74)
2
2
KEYSTONE/CLOS>
```

## Copyright and Acknowledgments

Copyright (C) 2020 GrammaTech, Inc.

This code is licensed under the MIT license. See the LICENSE file in
the project root for license terms.

This project is sponsored by the Office of Naval Research, One Liberty
Center, 875 N. Randolph Street, Arlington, VA 22203 under contract #
N68335-17-C-0700.  The content of the information does not necessarily
reflect the position or policy of the Government and no official
endorsement should be inferred.
