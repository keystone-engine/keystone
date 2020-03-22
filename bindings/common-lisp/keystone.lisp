;;;; keystone.lisp --- CFFI bindings to libkeystone.so
;;;;
;;;; Copyright (C) 2020 GrammaTech, Inc.
;;;;
;;;; This code is licensed under the MIT license. See the LICENSE file
;;;; in the project root for license terms.
;;;;
;;;; This project is sponsored by the Office of Naval Research, One
;;;; Liberty Center, 875 N. Randolph Street, Arlington, VA 22203 under
;;;; contract # N68335-17-C-0700.  The content of the information does
;;;; not necessarily reflect the position or policy of the Government
;;;; and no official endorsement should be inferred.
(in-package :keystone)
#+debug (declaim (optimize (debug 3)))

(cffi:define-foreign-library libkeystone
                             (t (:default "libkeystone")))
(use-foreign-library libkeystone)


;;;; CFFI definitions.
(defctype ks-engine (:pointer :void))

(defcenum ks-arch       ; Architecture type
  (:ARM 1)    ; ARM architecture (including Thumb, Thumb-2)
  :ARM64      ; ARM-64, also called AArch64
  :MIPS       ; Mips architecture
  :X86        ; X86 architecture (including x86 & x86-64)
  :PPC        ; PowerPC architecture (currently unsupported)
  :SPARC      ; Sparc architecture
  :SYSTEMZ    ; SystemZ architecture (S390X)
  :HEXAGON    ; Hexagon architecture
  :MAX)

(defcenum ks-mode                  ; Mode type
  (:LITTLE_ENDIAN 0)               ; little-endian mode (default mode)
  (:BIG_ENDIAN #.(ash 1 30))       ; big-endian mode
  ;; arm / arm64
  (:ARM #.(ash 1 0))                 ; ARM mode
  (:THUMB #.(ash 1 4))               ; THUMB mode (including Thumb-2)
  (:V8 #.(ash 1 6))                  ; ARMv8 A32 encodings for ARM
  ;; mips
  (:MICRO #.(ash 1 4))               ; MicroMips mode
  (:MIPS3 #.(ash 1 5))               ; Mips III ISA
  (:MIPS32R6 #.(ash 1 6))            ; Mips32r6 ISA
  (:MIPS32 #.(ash 1 2))              ; Mips32 ISA
  (:MIPS64 #.(ash 1 3))              ; Mips64 ISA
  ;; x86 / x64
  (:16 #.(ash 1 1))                  ; 16-bit mode
  (:32 #.(ash 1 2))                  ; 32-bit mode
  (:64 #.(ash 1 3))                  ; 64-bit mode
  ;; ppc
  (:PPC32 #.(ash 1 2))               ; 32-bit mode
  (:PPC64 #.(ash 1 3))               ; 64-bit mode
  (:QPX #.(ash 1 4))                 ; Quad Processing eXtensions mode
  ;; sparc
  (:SPARC32 #.(ash 1 2))                ; 32-bit mode
  (:SPARC64 #.(ash 1 3))                ; 64-bit mode
  (:V9 #.(ash 1 4)) )                   ; SparcV9 mode

(defcenum ks-error  ; All type of errors encountered by Keystone API.
  (:OK 0)           ; No error: everything was fine
  :NOMEM            ; Out-Of-Memory error: ks_open(), ks_emulate()
  :ARCH             ; Unsupported architecture: ks_open()
  :HANDLE           ; Invalid handle
  :MODE             ; Invalid/unsupported mode: ks_open()
  :VERSION          ; Unsupported version (bindings)
  :OPT_INVALID      ; Unsupported option
  ;; generic input assembly errors - parser specific
  (:ASM_EXPR_TOKEN 128)      ; unknown token in expression
  :ASM_DIRECTIVE_VALUE_RANGE ; literal value out of range for directive
  :ASM_DIRECTIVE_ID          ; expected identifier in directive
  :ASM_DIRECTIVE_TOKEN       ; unexpected token in directive
  :ASM_DIRECTIVE_STR         ; expected string in directive
  :ASM_DIRECTIVE_COMMA       ; expected comma in directive
  :ASM_DIRECTIVE_RELOC_NAME  ; expected relocation name in directive
  :ASM_DIRECTIVE_RELOC_TOKEN ; unexpected token in .reloc directive
  :ASM_DIRECTIVE_FPOINT      ; invalid floating point in directive
  :ASM_DIRECTIVE_UNKNOWN     ; unknown directive
  :ASM_DIRECTIVE_EQU         ; invalid equal directive
  :ASM_DIRECTIVE_INVALID     ; (generic) invalid directive
  :ASM_VARIANT_INVALID       ; invalid variant
  :ASM_EXPR_BRACKET ; brackets expression not supported on this target
  :ASM_SYMBOL_MODIFIER      ; unexpected symbol modifier following '@'
  :ASM_SYMBOL_REDEFINED     ; invalid symbol redefinition
  :ASM_SYMBOL_MISSING       ; cannot find a symbol
  :ASM_RPAREN               ; expected ')' in parentheses expression
  :ASM_STAT_TOKEN           ; unexpected token at start of statement
  :ASM_UNSUPPORTED          ; unsupported token yet
  :ASM_MACRO_TOKEN          ; unexpected token in macro instantiating
  :ASM_MACRO_PAREN          ; unbalanced parentheses in macro argument
  :ASM_MACRO_EQU      ; expected '=' after formal parameter identifier
  :ASM_MACRO_ARGS     ; too many positional arguments
  :ASM_MACRO_LEVELS_EXCEED ; macros cannot be nested more than 20 levels deep
  :ASM_MACRO_STR           ; invalid macro string
  :ASM_MACRO_INVALID       ; invalid macro (generic error)
  :ASM_ESC_BACKSLASH   ; unexpected backslash at end of escaped string
  :ASM_ESC_OCTAL       ; invalid octal escape sequence  (out of range)
  :ASM_ESC_SEQUENCE ; invalid escape sequence (unrecognized character)
  :ASM_ESC_STR      ; broken escape string
  :ASM_TOKEN_INVALID    ; invalid token
  :ASM_INSN_UNSUPPORTED ; this instruction is unsupported in this mode
  :ASM_FIXUP_INVALID    ; invalid fixup
  :ASM_LABEL_INVALID    ; invalid label
  :ASM_FRAGMENT_INVALID ; invalid fragment
  ;; generic input assembly errors - architecture specific
  (:ASM_INVALIDOPERAND 512)
  :ASM_MISSINGFEATURE
  :ASM_MNEMONICFAIL)

(defcenum ks-opt-type         ; Runtime option for the Keystone engine
  (:SYNTAX 1))                ; Choose syntax for input assembly

(defcenum ks-opt-value ; Runtime option value (associated with ks_opt_type above)
  (:SYNTAX-INTEL #.(ash 1 0)) ; X86 Intel syntax - default on X86 (KS_OPT_SYNTAX).
  (:SYNTAX-ATT   #.(ash 1 1)) ; X86 ATT asm syntax (KS_OPT_SYNTAX).
  (:SYNTAX-NASM  #.(ash 1 2)) ; X86 Nasm syntax (KS_OPT_SYNTAX).
  (:SYNTAX-MASM  #.(ash 1 3)) ; X86 Masm syntax (KS_OPT_SYNTAX) - unsupported yet.
  (:SYNTAX-GAS   #.(ash 1 4)))   ; X86 GNU GAS syntax (KS_OPT_SYNTAX).

(defcfun "ks_version" :unsigned-int
  "Return combined API version & major and minor version numbers.

@major: major number of API version
@minor: minor number of API version

@return hexical number as (major << 8 | minor), which encodes both
    major & minor versions.
    NOTE: This returned value can be compared with version number made
    with macro KS_MAKE_VERSION

For example, second API version would return 1 in @major, and 1 in @minor
The return value would be 0x0101

NOTE: if you only care about returned value, but not major and minor values,
set both @major & @minor arguments to NULL."
  (major :unsigned-int)
  (minor :unsigned-int))

(defcfun "ks_arch_supported" :boolean
  "Determine if the given architecture is supported by this library.

@arch: architecture type (KS_ARCH_*)

@return True if this library supports the given arch."
  (arch ks-arch))

(defcfun "ks_open" ks-error
  "Create new instance of Keystone engine.

@arch: architecture type (KS_ARCH_*)
@mode: hardware mode. This is combined of KS_MODE_*
@ks: pointer to ks_engine, which will be updated at return time

@return KS_ERR_OK on success, or other value on failure (refer to ks_err enum
  for detailed error)."
  (arch ks-arch)
  (mode ks-mode)
  (engine (:pointer ks-engine)))

(defcfun "ks_close" ks-error
  "Close KS instance: MUST do to release the handle when it is not used anymore.
NOTE: this must be called only when there is no longer usage of Keystone.
The reason is the this API releases some cached memory, thus access to any
Keystone API after ks_close() might crash your application.
After this, @ks is invalid, and nolonger usable.

@ks: pointer to a handle returned by ks_open()

@return KS_ERR_OK on success, or other value on failure (refer to ks_err enum
  for detailed error)."
  (engine ks-engine))

(defcfun "ks_errno" ks-error
  "Report the last error number when some API function fail.
Like glibc's errno, ks_errno might not retain its old error once accessed.

@ks: handle returned by ks_open()

@return: error code of ks_err enum type (KS_ERR_*, see above)"
  (engine ks-engine))

(defcfun "ks_strerror" :string
  "Return a string describing given error code.

@code: error code (see KS_ERR_* above)

@return: returns a pointer to a string that describes the error code
  passed in the argument @code"
  (code ks-error))

(defcfun "ks_option" ks-error
  "Set option for Keystone engine at runtime

@ks: handle returned by ks_open()
@type: type of option to be set
@value: option value corresponding with @type

@return: KS_ERR_OK on success, or other value on failure.
Refer to ks_err enum for detailed error."
  (engine ks-engine)
  (type ks-opt-type)
  (value size-t))

(defcfun "ks_asm" ks-error
  "Assemble a string given its the buffer, size, start address and number
of instructions to be decoded.
This API dynamically allocate memory to contain assembled instruction.
Resulted array of bytes containing the machine code  is put into @*encoding

NOTE 1: this API will automatically determine memory needed to contain
output bytes in *encoding.

NOTE 2: caller must free the allocated memory itself to avoid memory leaking.

@ks: handle returned by ks_open()
@str: NULL-terminated assembly string. Use ; or \n to separate statements.
@address: address of the first assembly instruction, or 0 to ignore.
@encoding: array of bytes containing encoding of input assembly string.
          NOTE: *encoding will be allocated by this function, and should be freed
          with ks_free() function.
@encoding_size: size of *encoding
@stat_count: number of statements successfully processed

@return: 0 on success, or -1 on failure.

On failure, call ks_errno() for error code."
  (ks ks-engine)
  (str :string)
  (address :uint64)
  (encoding (:pointer (:pointer :unsigned-char)))
  (encoding-size (:pointer size-t))
  (stat-count (:pointer size-t)))

(defcfun "ks_free" :void
  "Free memory allocated by ks_asm()

@p: memory allocated in @encoding argument of ks_asm()"
  (p (:pointer :unsigned-char)))
