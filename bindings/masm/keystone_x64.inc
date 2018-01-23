;--------------------------------------------------------------------------------------------------------
; Keystone_x64.inc for asm x64 - fearless 2017 - www.github.com/mrfearless - www.LetTheLight.in
;
; Include file for keystone.dll (x64) exports, constants and structures.
;
; This is a conversion of the original files: keystone.h, & x86.h to a format that will work with JWasm, 
; UASM (http://www.terraspace.co.uk/uasm.html) and other x64 assemblers (possibly).
;
;--------------------------------------------------------------------------------------------------------

; Misc
CS_MNEMONIC_SIZE                EQU 32
size_t                          TYPEDEF QWORD
csh                             TYPEDEF size_t

; Keystone API version
KS_API_MAJOR                    EQU 0
KS_API_MINOR                    EQU 9

; Package version
KS_VERSION_MAJOR                EQU KS_API_MAJOR   
KS_VERSION_MINOR                EQU KS_API_MINOR   
KS_VERSION_EXTRA                EQU 1
KS_MAKE_VERSION                 EQU 9d ; ((major << 8) + minor)

; Architecture type ks_arch
KS_ARCH_ARM                     EQU 1       ; ARM architecture (including Thumb, Thumb-2)
KS_ARCH_ARM64                   EQU 2       ; ARM-64, also called AArch64
KS_ARCH_MIPS                    EQU 3       ; Mips architecture
KS_ARCH_X86                     EQU 4       ; X86 architecture (including x86 & x86-64)
KS_ARCH_PPC                     EQU 5       ; PowerPC architecture (currently unsupported)
KS_ARCH_SPARC                   EQU 6       ; Sparc architecture
KS_ARCH_SYSTEMZ                 EQU 7       ; SystemZ architecture (S390X)
KS_ARCH_HEXAGON                 EQU 8       ; Hexagon architecture
KS_ARCH_MAX                     EQU 9       ; 

; Mode type ks_mode
KS_MODE_LITTLE_ENDIAN           EQU 0       ; little-endian mode (default mode)
KS_MODE_BIG_ENDIAN              EQU 1073741824; = 1 << 30 - big-endian mode
KS_MODE_ARM                     EQU 0       ; 32-bit ARM
KS_MODE_THUMB                   EQU 16d     ; = 1 << 4 - ARM's Thumb mode, including Thumb-2
KS_MODE_V8                      EQU 64d     ; = 1 << 6 - ARMv8 A32 encodings for ARM
KS_MODE_MICRO                   EQU 16d     ; = 1 << 4 - MicroMips mode (MIPS)
KS_MODE_MIPS3                   EQU 32d     ; = 1 << 5 - Mips III ISA
KS_MODE_MIPS32R6                EQU 64d     ; = 1 << 6 - Mips32r6 ISA
KS_MODE_MIPS32                  EQU 4       ; = 1 << 2 - Mips32 ISA
KS_MODE_MIPS64                  EQU 8       ; = 1 << 3 - Mips64 ISA
KS_MODE_16                      EQU 2       ; = 1 << 1 - 16-bit mode
KS_MODE_32                      EQU 4       ; = 1 << 2 - 32-bit mode
KS_MODE_64                      EQU 8       ; = 1 << 3 - 64-bit mode
KS_MODE_PPC32                   EQU 4       ; = 1 << 2 - 32-bit mode
KS_MODE_PPC64                   EQU 8       ; = 1 << 3 - 64-bit mode
KS_MODE_QPX                     EQU 16d     ; = 1 << 4 - Quad Processing eXtensions mode
KS_MODE_SPARC32                 EQU 4       ; = 1 << 2 - 32-bit mode
KS_MODE_SPARC64                 EQU 8       ; = 1 << 3 - 64-bit mode    
KS_MODE_V9                      EQU 16d     ; = 1 << 4 - SparcV9 mode (Sparc)

; Errors
KS_ERR_ASM                      EQU 128     ; All generic errors related to input assembly >= KS_ERR_ASM
KS_ERR_ASM_ARCH                 EQU 512     ; All architecture-specific errors related to input assembly >=

; All type of errors encountered by Keystone API ks_err
KS_ERR_OK                       EQU 0       ; No error: everything was fine
KS_ERR_NOMEM                    EQU 1       ; Out-Of-Memory error: ks_open(), ks_emulate()
KS_ERR_ARCH                     EQU 2       ; Unsupported architecture: ks_open()
KS_ERR_HANDLE                   EQU 3       ; Invalid handle
KS_ERR_MODE                     EQU 4       ; Invalid/unsupported mode: ks_open()
KS_ERR_VERSION                  EQU 5       ; Unsupported version (bindings)
KS_ERR_OPT_INVALID              EQU 6       ; Unsupported option

; generic input assembly errors - parser specific
KS_ERR_ASM_EXPR_TOKEN           EQU KS_ERR_ASM  ; unknown token in expression
KS_ERR_ASM_DIRECTIVE_VALUE_RANGE EQU 129    ; literal value out of range for directive
KS_ERR_ASM_DIRECTIVE_ID         EQU 130     ; expected identifier in directive
KS_ERR_ASM_DIRECTIVE_TOKEN      EQU 131     ; unexpected token in directive
KS_ERR_ASM_DIRECTIVE_STR        EQU 132     ; expected string in directive
KS_ERR_ASM_DIRECTIVE_COMMA      EQU 133     ; expected comma in directive
KS_ERR_ASM_DIRECTIVE_RELOC_NAME EQU 134     ; expected relocation name in directive
KS_ERR_ASM_DIRECTIVE_RELOC_TOKEN EQU 135    ; unexpected token in .reloc directive
KS_ERR_ASM_DIRECTIVE_FPOINT     EQU 136     ; invalid floating point in directive
KS_ERR_ASM_DIRECTIVE_UNKNOWN    EQU 137     ; unknown directive
KS_ERR_ASM_DIRECTIVE_EQU        EQU 138     ; invalid equal directive
KS_ERR_ASM_DIRECTIVE_INVALID    EQU 139     ; (generic) invalid directive
KS_ERR_ASM_VARIANT_INVALID      EQU 140     ; invalid variant
KS_ERR_ASM_EXPR_BRACKET         EQU 141     ; brackets expression not supported on this target
KS_ERR_ASM_SYMBOL_MODIFIER      EQU 142     ; unexpected symbol modifier following '@'
KS_ERR_ASM_SYMBOL_REDEFINED     EQU 143     ; invalid symbol redefinition
KS_ERR_ASM_SYMBOL_MISSING       EQU 144     ; cannot find a symbol
KS_ERR_ASM_RPAREN               EQU 145     ; expected ')' in parentheses expression
KS_ERR_ASM_STAT_TOKEN           EQU 146     ; unexpected token at start of statement
KS_ERR_ASM_UNSUPPORTED          EQU 147     ; unsupported token yet
KS_ERR_ASM_MACRO_TOKEN          EQU 148     ; unexpected token in macro instantiation
KS_ERR_ASM_MACRO_PAREN          EQU 149     ; unbalanced parentheses in macro argument
KS_ERR_ASM_MACRO_EQU            EQU 150     ; expected '=' after formal parameter identifier
KS_ERR_ASM_MACRO_ARGS           EQU 151     ; too many positional arguments
KS_ERR_ASM_MACRO_LEVELS_EXCEED  EQU 152     ; macros cannot be nested more than 20 levels deep
KS_ERR_ASM_MACRO_STR            EQU 153     ; invalid macro string
KS_ERR_ASM_MACRO_INVALID        EQU 154     ; invalid macro (generic error)
KS_ERR_ASM_ESC_BACKSLASH        EQU 155     ; unexpected backslash at end of escaped string
KS_ERR_ASM_ESC_OCTAL            EQU 156     ; invalid octal escape sequence  (out of range)
KS_ERR_ASM_ESC_SEQUENCE         EQU 157     ; invalid escape sequence (unrecognized character)
KS_ERR_ASM_ESC_STR              EQU 158     ; broken escape string
KS_ERR_ASM_TOKEN_INVALID        EQU 159     ; invalid token
KS_ERR_ASM_INSN_UNSUPPORTED     EQU 160     ; this instruction is unsupported in this mode
KS_ERR_ASM_FIXUP_INVALID        EQU 161     ; invalid fixup
KS_ERR_ASM_LABEL_INVALID        EQU 162     ; invalid label
KS_ERR_ASM_FRAGMENT_INVALID     EQU 163     ; invalid fragment

; generic input assembly errors - architecture specific
KS_ERR_ASM_INVALIDOPERAND       EQU KS_ERR_ASM_ARCH,
KS_ERR_ASM_MISSINGFEATURE       EQU 513
KS_ERR_ASM_MNEMONICFAIL         EQU 514

; ks_err_asm_x86
KS_ERR_ASM_X86_INVALIDOPERAND   EQU KS_ERR_ASM_ARCH
KS_ERR_ASM_X86_MISSINGFEATURE   EQU KS_ERR_ASM_MISSINGFEATURE
KS_ERR_ASM_X86_MNEMONICFAIL     EQU KS_ERR_ASM_MNEMONICFAIL

; Runtime option for the Keystone engine ks_opt_type
KS_OPT_SYNTAX                   EQU 1       ; Choose syntax for input assembly
KS_OPT_SYM_RESOLVER             EQU 2       ; Set symbol resolver callback

; Runtime option value (associated with ks_opt_type above) ks_opt_value
KS_OPT_SYNTAX_INTEL             EQU 1       ; = 1 << 0, // X86 Intel syntax - default on X86 (KS_OPT_SYNTAX).
KS_OPT_SYNTAX_ATT               EQU 2       ; = 1 << 1, // X86 ATT asm syntax (KS_OPT_SYNTAX).
KS_OPT_SYNTAX_NASM              EQU 4       ; = 1 << 2, // X86 Nasm syntax (KS_OPT_SYNTAX).
KS_OPT_SYNTAX_MASM              EQU 8       ; = 1 << 3, // X86 Masm syntax (KS_OPT_SYNTAX) - unsupported yet.
KS_OPT_SYNTAX_GAS               EQU 16      ; = 1 << 4, // X86 GNU GAS syntax (KS_OPT_SYNTAX).
KS_OPT_SYNTAX_RADIX16           EQU 32      ; = 1 << 5, // All immediates are in hex format (i.e 12 is 0x12)

; Keystone Functions for x64 assemblers: JWasm/UASM
ks_version                      PROTO :QWORD, :QWORD ; int* major, int* minor
ks_arch_supported               PROTO :QWORD ; ks_arch arch
ks_open                         PROTO :QWORD, :QWORD, :QWORD ; ks_arch arch, int mode, ks_engine** ks
ks_close                        PROTO :QWORD ; ks_engine* ks
ks_errno                        PROTO :QWORD ; ks_engine* ks
ks_strerror                     PROTO :QWORD ; ks_err code
ks_option                       PROTO :QWORD, :QWORD, :QWORD ; ks_engine* ks, ks_opt_type type, size_t value
ks_asm                          PROTO :QWORD, :QWORD, :QWORD, :QWORD, :QWORD, :QWORD ; ks_engine* ks, const char* string, int64_t address, unsigned char** encoding, size_t* encoding_size, size_t* stat_count
ks_free                         PROTO :QWORD ; unsigned char* p

; Resolver callback to provide value for a missing symbol in @symbol.
; To handle a symbol, the resolver must put value of the symbol in @value,
; then returns True.
; If we do not resolve a missing symbol, this function must return False.
; In that case, ks_asm() would eventually return with error KS_ERR_ASM_SYMBOL_MISSING.
;
; To register the resolver, pass its function address to ks_option(), using
; option KS_OPT_SYM_RESOLVER. typedef bool *ks_sym_resolver)(const char* symbol, uint64_t* value
;
; Invoke ks_option, ks, KS_OPT_SYM_RESOLVER, Addr ks_sym_resolver
;

ks_sym_resolver                 PROTO :QWORD, :QWORD ; const char* symbol, uint64_t* value