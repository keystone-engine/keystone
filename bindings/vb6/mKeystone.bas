Attribute VB_Name = "mKeyStone"
Option Explicit

'Keystone Assembly Engine bindings for VB6
'Contributed by FireEye FLARE Team
'Author:  David Zimmer <david.zimmer@fireeye.com>, <dzzie@yahoo.com>
'License: Apache 2.0
'Copyright: FireEye 2017

'NOTE: the VB code was built and tested against the latest binary release: Keystone 0.9.1
'      I will enabled the symbol resolver once it makes it into the stable release

Public hLib As Long
Public version As String
Public vMajor As Long
Public vMinor As Long

Public Enum ks_arch
    KS_ARCH_ARM = 1 ' ARM architecture (including Thumb, Thumb-2)
    KS_ARCH_ARM64   ' ARM-64, also called AArch64
    KS_ARCH_MIPS    ' Mips architecture
    KS_ARCH_X86     ' X86 architecture (including x86 & x86-64)
    KS_ARCH_PPC     ' PowerPC architecture (currently unsupported)
    KS_ARCH_SPARC   ' Sparc architecture
    KS_ARCH_SYSTEMZ ' SystemZ architecture (S390X)
    KS_ARCH_HEXAGON ' Hexagon architecture
    KS_ARCH_MAX
End Enum

Public Enum ks_mode
    KS_MODE_LITTLE_ENDIAN = 0       ' little-endian mode (default mode)
    KS_MODE_BIG_ENDIAN = &H40000000 ' big-endian mode
    '  arm / arm64
    KS_MODE_ARM = 1                 ' ARM mode
    KS_MODE_THUMB = &H10            ' THUMB mode (including Thumb-2)
    KS_MODE_V8 = &H40               ' ARMv8 A32 encodings for ARM
    '  mips
    KS_MODE_MICRO = &H10            ' MicroMips mode
    KS_MODE_MIPS3 = &H20            ' Mips III ISA
    KS_MODE_MIPS32R6 = &H40         ' Mips32r6 ISA
    KS_MODE_MIPS32 = 4              ' Mips32 ISA
    KS_MODE_MIPS64 = 8              ' Mips64 ISA
    '  x86 / x64
    KS_MODE_16 = 2                  ' 16-bit mode
    KS_MODE_32 = 4                  ' 32-bit mode
    KS_MODE_64 = 8                  ' 64-bit mode
    '  ppc
    KS_MODE_PPC32 = 4               ' 32-bit mode
    KS_MODE_PPC64 = 8               ' 64-bit mode
    KS_MODE_QPX = &H10              ' Quad Processing eXtensions mode
    '  sparc
    KS_MODE_SPARC32 = 4             ' 32-bit mode
    KS_MODE_SPARC64 = 8             ' 64-bit mode
    KS_MODE_V9 = &H10               ' SparcV9 mode
End Enum

'All generic errors related to input assembly >= KS_ERR_ASM
Public Const KS_ERR_ASM = 128

'All architecture-specific errors related to input assembly >= KS_ERR_ASM_ARCH
Public Const KS_ERR_ASM_ARCH = 512

'All type of errors encountered by Keystone API.
Public Enum ks_err                   ' All type of errors encountered by Keystone API.
    KS_ERR_OK = 0                    ' No error: everything was fine
    KS_ERR_NOMEM                     ' Out-Of-Memory error: ks_open(), ks_emulate()
    KS_ERR_ARCH                      ' Unsupported architecture: ks_open()
    KS_ERR_HANDLE                    ' Invalid handle
    KS_ERR_MODE                      ' Invalid/unsupported mode: ks_open()
    KS_ERR_VERSION                   ' Unsupported version (bindings)
    KS_ERR_OPT_INVALID               ' Unsupported option
                                     '  generic input assembly errors - parser specific
    KS_ERR_ASM_EXPR_TOKEN = 128      'KS_ERR_ASM ' unknown token in expression
    KS_ERR_ASM_DIRECTIVE_VALUE_RANGE ' literal value out of range for directive
    KS_ERR_ASM_DIRECTIVE_ID          ' expected identifier in directive
    KS_ERR_ASM_DIRECTIVE_TOKEN       ' unexpected token in directive
    KS_ERR_ASM_DIRECTIVE_STR         ' expected string in directive
    KS_ERR_ASM_DIRECTIVE_COMMA       ' expected comma in directive
    KS_ERR_ASM_DIRECTIVE_RELOC_NAME  ' expected relocation name in directive
    KS_ERR_ASM_DIRECTIVE_RELOC_TOKEN ' unexpected token in .reloc directive
    KS_ERR_ASM_DIRECTIVE_FPOINT      ' invalid floating point in directive
    KS_ERR_ASM_DIRECTIVE_UNKNOWN     ' unknown directive
    KS_ERR_ASM_DIRECTIVE_EQU         ' invalid equal directive
    KS_ERR_ASM_DIRECTIVE_INVALID     ' (generic) invalid directive
    KS_ERR_ASM_VARIANT_INVALID       ' invalid variant
    KS_ERR_ASM_EXPR_BRACKET          ' brackets expression not supported on this target
    KS_ERR_ASM_SYMBOL_MODIFIER       ' unexpected symbol modifier following '@'
    KS_ERR_ASM_SYMBOL_REDEFINED      ' invalid symbol redefinition
    KS_ERR_ASM_SYMBOL_MISSING        ' cannot find a symbol
    KS_ERR_ASM_RPAREN                ' expected ')' in parentheses expression
    KS_ERR_ASM_STAT_TOKEN            ' unexpected token at start of statement
    KS_ERR_ASM_UNSUPPORTED           ' unsupported token yet
    KS_ERR_ASM_MACRO_TOKEN           ' unexpected token in macro instantiation
    KS_ERR_ASM_MACRO_PAREN           ' unbalanced parentheses in macro argument
    KS_ERR_ASM_MACRO_EQU             ' expected '=' after formal parameter identifier
    KS_ERR_ASM_MACRO_ARGS            ' too many positional arguments
    KS_ERR_ASM_MACRO_LEVELS_EXCEED   ' macros cannot be nested more than 20 levels deep
    KS_ERR_ASM_MACRO_STR             ' invalid macro string
    KS_ERR_ASM_MACRO_INVALID         ' invalid macro (generic error)
    KS_ERR_ASM_ESC_BACKSLASH         ' unexpected backslash at end of escaped string
    KS_ERR_ASM_ESC_OCTAL             ' invalid octal escape sequence  (out of range)
    KS_ERR_ASM_ESC_SEQUENCE          ' invalid escape sequence (unrecognized character)
    KS_ERR_ASM_ESC_STR               ' broken escape string
    KS_ERR_ASM_TOKEN_INVALID         ' invalid token
    KS_ERR_ASM_INSN_UNSUPPORTED      ' this instruction is unsupported in this mode
    KS_ERR_ASM_FIXUP_INVALID         ' invalid fixup
    KS_ERR_ASM_LABEL_INVALID         ' invalid label
    KS_ERR_ASM_FRAGMENT_INVALID      ' invalid fragment
                                     '  generic input assembly errors - architecture specific
    KS_ERR_ASM_INVALIDOPERAND = 512  'KS_ERR_ASM_ARCH
    KS_ERR_ASM_MISSINGFEATURE
    KS_ERR_ASM_MNEMONICFAIL
End Enum

'Runtime option for the Keystone engine
Public Enum ks_opt_type     ' Runtime option for the Keystone engine
    KS_OPT_SYNTAX = 1 ' Choose syntax for input assembly
End Enum


'Runtime option value (associated with ks_opt_type above)
Public Enum ks_opt_value
    KS_OPT_SYNTAX_INTEL = 1   ' X86 Intel syntax - default on X86 (KS_OPT_SYNTAX).
    KS_OPT_SYNTAX_ATT = 2     ' X86 ATT asm syntax (KS_OPT_SYNTAX).
    KS_OPT_SYNTAX_NASM = 4    ' X86 Nasm syntax (KS_OPT_SYNTAX).
    KS_OPT_SYNTAX_MASM = 8    ' X86 Masm syntax (KS_OPT_SYNTAX) - unsupported yet.
    KS_OPT_SYNTAX_GAS = &H10  ' X86 GNU GAS syntax (KS_OPT_SYNTAX).
End Enum

Public Enum KS_ERR_ASM
    KS_ERR_ASM_INVALIDOPERAND = 512  'KS_ERR_ASM_ARCH
    KS_ERR_ASM_MISSINGFEATURE
    KS_ERR_ASM_MNEMONICFAIL
End Enum

' Resolver callback to provide value for a missing symbol in @symbol.
' To handle a symbol, the resolver must put value of the symbol in @value,
' then returns True.
' If we do not resolve a missing symbol, this function must return False.
' In that case, ks_asm() would eventually return with error KS_ERR_ASM_SYMBOL_MISSING.
'
' To register the resolver, pass its function address to ks_option(), using
' option KS_OPT_SYM_RESOLVER. For example, see samples/sample.c.
'typedef bool (*ks_sym_resolver)(const char *symbol, uint64_t *value);
'public function vbSymResolver(byval symbol as long , byref value as currency) as long

'void __stdcall setResolver(ks_engine *ks, unsigned int lpfnVBResolver){
'Public Declare Function setResolver Lib "vbKeyStone.dll" (ByVal hEngine As Long, ByVal lpfnVBResolver As Long) As Long


'/*
' Return combined API version & major and minor version numbers.
'
' @major: major number of API version
' @minor: minor number of API version
'
' @return hexical number as (major << 8 | minor), which encodes both
'     major & minor versions.
'     NOTE: This returned value can be compared with version number made
'     with macro KS_MAKE_VERSION
'
' For example, second API version would return 1 in @major, and 1 in @minor
' The return value would be 0x0101
'
' NOTE: if you only care about returned value, but not major and minor values,
' set both @major & @minor arguments to NULL.
'*/
'unsigned int ks_version(unsigned int *major, unsigned int *minor);
Public Declare Function ks_version Lib "vbKeyStone.dll" Alias "vs_version" (ByRef major As Long, ByRef minor As Long) As Long

'
'
'/*
' Determine if the given architecture is supported by this library.
'
' @arch: architecture type (KS_ARCH_*)
'
' @return True if this library supports the given arch.
'*/
'bool ks_arch_supported(ks_arch arch);
Public Declare Function ks_arch_supported Lib "vbKeyStone.dll" Alias "vs_arch_supported" (ByVal arch As ks_arch) As Long

'
'
'/*
' Create new instance of Keystone engine.
'
' @arch: architecture type (KS_ARCH_*)
' @mode: hardware mode. This is combined of KS_MODE_*
' @ks: pointer to ks_engine, which will be updated at return time
'
' @return KS_ERR_OK on success, or other value on failure (refer to ks_err enum
'   for detailed error).
'*/
'ks_err ks_open(ks_arch arch, int mode, ks_engine **ks);
Public Declare Function ks_open Lib "vbKeyStone.dll" Alias "vs_open" (ByVal arch As ks_arch, ByVal mode As Long, ByRef hEngine As Long) As ks_err


'
'/*
' Close KS instance: MUST do to release the handle when it is not used anymore.
' NOTE: this must be called only when there is no longer usage of Keystone.
' The reason is the this API releases some cached memory, thus access to any
' Keystone API after ks_close() might crash your application.
' After this, @ks is invalid, and nolonger usable.
'
' @ks: pointer to a handle returned by ks_open()
'
' @return KS_ERR_OK on success, or other value on failure (refer to ks_err enum
'   for detailed error).
'*/
'ks_err ks_close(ks_engine *ks);
Public Declare Function ks_close Lib "vbKeyStone.dll" Alias "vs_close" (ByVal hEngine As Long) As ks_err


'
'/*
' Report the last error number when some API function fail.
' Like glibc's errno, ks_errno might not retain its old error once accessed.
'
' @ks: handle returned by ks_open()
'
' @return: error code of ks_err enum type (KS_ERR_*, see above)
'*/
'ks_err ks_errno(ks_engine *ks);
Public Declare Function ks_errno Lib "vbKeyStone.dll" Alias "vs_errno" (ByVal hEngine As Long) As ks_err


'
'/*
' Return a string describing given error code.
'
' @code: error code (see KS_ERR_* above)
'
' @return: returns a pointer to a string that describes the error code
'   passed in the argument @code
' */
'const char *ks_strerror(ks_err code);
Public Declare Function ks_strerror Lib "vbKeyStone.dll" Alias "vs_strerror" (ByVal code As ks_err) As Long


'
'/*
' Set option for Keystone engine at runtime
'
' @ks: handle returned by ks_open()
' @type: type of option to be set
' @value: option value corresponding with @type
'
' @return: KS_ERR_OK on success, or other value on failure.
' Refer to ks_err enum for detailed error.
'*/
'ks_err ks_option(ks_engine *ks, ks_opt_type type, size_t value);
Public Declare Function ks_option Lib "vbKeyStone.dll" Alias "vs_option" (ByVal hEngine As Long, ByVal opt As ks_opt_type, ByVal value As Long) As ks_err


'/*
' Assemble a string given its the buffer, size, start address and number
' of instructions to be decoded.
' This API dynamically allocate memory to contain assembled instruction.
' Resulted array of bytes containing the machine code  is put into @*encoding
'
' NOTE 1: this API will automatically determine memory needed to contain
' output bytes in *encoding.
'
' NOTE 2: caller must free the allocated memory itself to avoid memory leaking.
'
' @ks: handle returned by ks_open()
' @str: NULL-terminated assembly string. Use ; or \n to separate statements.
' @address: address of the first assembly instruction, or 0 to ignore.
' @encoding: array of bytes containing encoding of input assembly string.
'       NOTE: *encoding will be allocated by this function, and should be freed
'       with ks_free() function.
' @encoding_size: size of *encoding
' @stat_count: number of statements successfully processed
'
' @return: 0 on success, or -1 on failure.
'
' On failure, call ks_errno() for error code.
'*/

'int ks_asm(ks_engine *ks,
'        const char *string,
'        uint64_t address,
'        unsigned char **encoding, size_t *encoding_size,
'        size_t *stat_count);

Public Declare Function ks_asm Lib "vbKeyStone.dll" Alias "vs_asm" ( _
    ByVal hEngine As Long, _
    ByVal asm As String, _
    ByVal address As Currency, _
    ByRef bytesOut As Long, _
    ByRef encodedSize As Long, _
    ByRef linesAssembled As Long _
) As ks_err



'/*
' Free memory allocated by ks_asm()
' @p: memory allocated in @encoding argument of ks_asm()
'*/
'void ks_free(unsigned char *p);
Public Declare Sub ks_free Lib "vbKeyStone.dll" Alias "vs_free" (ByVal buf As Long)

Private Declare Function lstrcpy Lib "kernel32" Alias "lstrcpyA" (ByVal lpString1 As String, ByVal lpString2 As String) As Long
Private Declare Function lstrlen Lib "kernel32" Alias "lstrlenA" (ByVal lpString As Long) As Long

Function cstr2vb(lpStr As Long) As String

    Dim length As Long
    Dim buf() As Byte

    If lpStr = 0 Then Exit Function

    length = lstrlen(lpStr)
    If length < 1 Then Exit Function
    
    ReDim buf(1 To length)
    CopyMemory buf(1), ByVal lpStr, length

    cstr2vb = StrConv(buf, vbUnicode, &H409)

End Function

Function err2str(e As ks_err) As String
    Dim lpStr As Long
    lpStr = ks_strerror(e)
    err2str = cstr2vb(lpStr)
End Function

Function ks_arch2str(v As ks_arch) As String
     Dim r As String
    If v = KS_ARCH_ARM Then r = "KS_ARCH_ARM"
    If v = KS_ARCH_ARM64 Then r = "KS_ARCH_ARM64"
    If v = KS_ARCH_MIPS Then r = "KS_ARCH_MIPS"
    If v = KS_ARCH_X86 Then r = "KS_ARCH_X86"
    If v = KS_ARCH_PPC Then r = "KS_ARCH_PPC"
    If v = KS_ARCH_SPARC Then r = "KS_ARCH_SPARC"
    If v = KS_ARCH_SYSTEMZ Then r = "KS_ARCH_SYSTEMZ"
    If v = KS_ARCH_HEXAGON Then r = "KS_ARCH_HEXAGON"
    If v = KS_ARCH_MAX Then r = "KS_ARCH_MAX"
    If Len(r) = 0 Then r = "Unknown: " & Hex(v)
    ks_arch2str = r
End Function

Function ks_opt_value2str(v As ks_opt_value) As String
    Dim r As String
    If v = KS_OPT_SYNTAX_INTEL Then r = "KS_OPT_SYNTAX_INTEL"
    If v = KS_OPT_SYNTAX_ATT Then r = "KS_OPT_SYNTAX_ATT"
    If v = KS_OPT_SYNTAX_NASM Then r = "KS_OPT_SYNTAX_NASM"
    If v = KS_OPT_SYNTAX_MASM Then r = "KS_OPT_SYNTAX_MASM"
    If v = KS_OPT_SYNTAX_GAS Then r = "KS_OPT_SYNTAX_GAS"
    If Len(r) = 0 Then r = "Unknown: " & Hex(v)
    ks_opt_value2str = r
End Function

Private Function CheckPath(pth As String, Optional errMsg As String) As Long
    
    Dim hCap As Long, capPth As String, shimPth As String
    
    shimPth = pth & "\vbKeystone.dll"
    capPth = pth & "\keystone.dll"
    
    If Not FileExists(shimPth) Then Exit Function
       
    hCap = LoadLibrary(capPth)
    If hCap = 0 Then hCap = LoadLibrary("keystone.dll")
    If hCap = 0 Then errMsg = "Could not find keystone.dll"
    
    CheckPath = LoadLibrary(shimPth)
    'If CheckPath = 0 Then MsgBox Err.LastDllError
    
End Function

Public Function initDll(Optional ByRef r As CAsmResult) As Boolean
    
    Dim errMsg As String
    
    hLib = GetModuleHandle("vbKeystone.dll")
   
    If hLib = 0 Then hLib = CheckPath(App.path & "\bin\", errMsg)
    If hLib = 0 Then hLib = CheckPath(App.path & "\", errMsg)
    If hLib = 0 Then hLib = CheckPath(App.path & "\..\", errMsg)
    If hLib = 0 Then hLib = LoadLibrary("vbKeystone.dll")
    
    If hLib = 0 Then
        If Not r Is Nothing Then r.errMsg = errMsg & " Could not load vbKeystone.dll"
        Exit Function
    End If
        
    ks_version vMajor, vMinor
    version = vMajor & "." & vMinor
    initDll = True
    
End Function

'untested
'Public Function vbSymResolver(ByVal symbol As Long, ByRef value As Currency) As Long
'
'    Dim sym As String
'
'    sym = cstr2vb(symbol)
'
'    If sym = "_l1" Then
'        value = lng2Cur(&H1002)
'        vbSymResolver = 1
'    Else
'        vbSymResolver = 0
'    End If
'
'End Function
