function Invoke-Keystone {
<#
.SYNOPSIS
	Powershell wrapper for Keystone (using inline C#).

	In effect the function directly parses the Keystone dll so it can support any
	features implemented by Keystone so long as function calls are prototyped in C#.

.DESCRIPTION
	Author: Ruben Boonen (@FuzzySec)
	License: BSD 3-Clause
	Required Dependencies: None
	Optional Dependencies: None

.EXAMPLE

	# Support for multi-line code blocks
	PS C:\> $Code = @"
	>> sub esp, 200
	>> pop eax
	>> pop ecx
	>> ret
	>> "@
	PS C:\> Invoke-Keystone -Architecture X86 -Mode 32 -Code $Code
	
	Bytes        : 9
	Instructions : 4
	PSArray      : {0x81, 0xEC, 0xC8, 0x00...}
	CArray       : {\x81, \xEC, \xC8, \x00...}
	RawArray     : {81, EC, C8, 00...}

.EXAMPLE

	# Invoke-Keystone emits objects
	PS C:\> $Code = @"
	>> sub esp, 200
	>> pop eax
	>> pop ecx
	>> ret
	>> "@
	PS C:\> $Object = Invoke-Keystone -Architecture X86 -Mode 32 -Code $Code
	PS C:\> $Object.RawArray -join ""
	81ECC80000005859C3
	PS C:\> $Object.CArray -join ""
	\x81\xEC\xC8\x00\x00\x00\x58\x59\xC3
	PS C:\> "`$Shellcode = {" + $($Object.PSArray -join ", ") + "}"
	$Shellcode = {0x81, 0xEC, 0xC8, 0x00, 0x00, 0x00, 0x58, 0x59, 0xC3}

#>

	param(
        [Parameter(Mandatory = $True)]
        [ValidateSet(
			'ARM',
			'ARM64',
			'MIPS',
			'X86',
			'PPC',
			'SPARC',
			'SYSZ',
			'HEXAGON',
			'MAX')
		]
        [String]$Architecture,
		
        [Parameter(Mandatory = $True)]
        [ValidateSet(
			'Little_Endian',
			'Big_Endian',
			'ARM',
			'THUMB',
			'V8',
			'MICRO',
			'MIPS3',
			'MIPS32R6',
			'MIPS32',
			'MIPS64',
			'16',
			'32',
			'64',
			'PPC32',
			'PPC64',
			'QPX',
			'SPARC32',
			'SPARC64',
			'V9')
		]
        [String]$Mode,

		[Parameter(Mandatory = $True)]
		[string]$Code,

		[Parameter(Mandatory = $False)]
		[String]$Syntax = "Intel"
    )

	Add-Type -TypeDefinition @"
	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	using System.Security.Principal;

	[Flags]
	public enum ks_err : int
	{
		KS_ERR_OK = 0,      /// No error: everything was fine
		KS_ERR_NOMEM,       /// Out-Of-Memory error: ks_open(), ks_emulate()
		KS_ERR_ARCH,        /// Unsupported architecture: ks_open()
		KS_ERR_HANDLE,      /// Invalid handle
		KS_ERR_MODE,        /// Invalid/unsupported mode: ks_open()
		KS_ERR_VERSION,     /// Unsupported version (bindings)
		KS_ERR_OPT_INVALID, /// Unsupported option
		
		/// generic input assembly errors - parser specific
		KS_ERR_ASM_EXPR_TOKEN = 128,        /// unknown token in expression
		KS_ERR_ASM_DIRECTIVE_VALUE_RANGE,   /// literal value out of range for directive
		KS_ERR_ASM_DIRECTIVE_ID,            /// expected identifier in directive
		KS_ERR_ASM_DIRECTIVE_TOKEN,         /// unexpected token in directive
		KS_ERR_ASM_DIRECTIVE_STR,           /// expected string in directive
		KS_ERR_ASM_DIRECTIVE_COMMA,         /// expected comma in directive
		KS_ERR_ASM_DIRECTIVE_RELOC_NAME,    /// expected relocation name in directive
		KS_ERR_ASM_DIRECTIVE_RELOC_TOKEN,   /// unexpected token in .reloc directive
		KS_ERR_ASM_DIRECTIVE_FPOINT,        /// invalid floating point in directive
		KS_ERR_ASM_DIRECTIVE_UNKNOWN,       /// unknown directive
		KS_ERR_ASM_DIRECTIVE_EQU,           /// invalid equal directive
		KS_ERR_ASM_DIRECTIVE_INVALID,       /// (generic) invalid directive
		KS_ERR_ASM_VARIANT_INVALID,         /// invalid variant
		KS_ERR_ASM_EXPR_BRACKET,            /// brackets expression not supported on this target
		KS_ERR_ASM_SYMBOL_MODIFIER,         /// unexpected symbol modifier following '@'
		KS_ERR_ASM_SYMBOL_REDEFINED,        /// invalid symbol redefinition
		KS_ERR_ASM_SYMBOL_MISSING,          /// cannot find a symbol
		KS_ERR_ASM_RPAREN,                  /// expected ')' in parentheses expression
		KS_ERR_ASM_STAT_TOKEN,              /// unexpected token at start of statement
		KS_ERR_ASM_UNSUPPORTED,             /// unsupported token yet
		KS_ERR_ASM_MACRO_TOKEN,             /// unexpected token in macro instantiation
		KS_ERR_ASM_MACRO_PAREN,             /// unbalanced parentheses in macro argument
		KS_ERR_ASM_MACRO_EQU,               /// expected '=' after formal parameter identifier
		KS_ERR_ASM_MACRO_ARGS,              /// too many positional arguments
		KS_ERR_ASM_MACRO_LEVELS_EXCEED,     /// macros cannot be nested more than 20 levels deep
		KS_ERR_ASM_MACRO_STR,               /// invalid macro string
		KS_ERR_ASM_MACRO_INVALID,           /// invalid macro (generic error)
		KS_ERR_ASM_ESC_BACKSLASH,           /// unexpected backslash at end of escaped string
		KS_ERR_ASM_ESC_OCTAL,               /// invalid octal escape sequence  (out of range)
		KS_ERR_ASM_ESC_SEQUENCE,            /// invalid escape sequence (unrecognized character)
		KS_ERR_ASM_ESC_STR,                 /// broken escape string
		KS_ERR_ASM_TOKEN_INVALID,           /// invalid token
		KS_ERR_ASM_INSN_UNSUPPORTED,        /// this instruction is unsupported in this mode
		KS_ERR_ASM_FIXUP_INVALID,           /// invalid fixup
		KS_ERR_ASM_LABEL_INVALID,           /// invalid label
		KS_ERR_ASM_FRAGMENT_INVALID,        /// invalid fragment
		
		/// generic input assembly errors - architecture specific
		KS_ERR_ASM_INVALIDOPERAND = 512,
		KS_ERR_ASM_MISSINGFEATURE,
		KS_ERR_ASM_MNEMONICFAIL,
	}
	
	public static class Keystone
	{
		[DllImport("keystone.dll")]
		public static extern ks_err ks_open(
			int arch,
			int mode,
			ref IntPtr handle);

		[DllImport("keystone.dll")]
		public static extern ks_err ks_option(
			IntPtr handle,
			int mode,
			uint value);

		[DllImport("keystone.dll")]
		public static extern int ks_asm(
			IntPtr handle,
			String assembly,
			ulong address,
			ref IntPtr encoding,
			ref uint encoding_size,
			ref uint stat_count);

		[DllImport("keystone.dll")]
		public static extern ks_err ks_errno(
			IntPtr handle);

		[DllImport("keystone.dll")]
		public static extern ks_err ks_close(
			IntPtr handle);

		[DllImport("keystone.dll")]
		public static extern void ks_free(
			IntPtr handle);
	}
"@

	# Architecture -> int
	New-Variable -Option Constant -Name ks_arch -Value @{
		"ARM"   = 1
		"ARM64" = 2
		"MIPS"  = 3
		"X86"   = 4
		# unsupported -> keystone.h
		"PPC"   = 5
		"SPARC" = 6
		"SYSZ"  = 7
		"HEXAGON" = 8
		"MAX"   = 9
	}

	# Mode -> int
	New-Variable -Option Constant -Name ks_mode -Value @{
		"Little_Endian" = 0
		"Big_Endian"    = 1073741824
		"ARM"           = 1
		"THUMB"         = 16
		"V8"            = 64
		"MICRO"         = 16
		"MIPS3"         = 32
		"MIPS32R6"      = 64
		"MIPS32"        = 4
		"MIPS64"        = 8
		"16"            = 2
		"32"            = 4
		"64"            = 8
		"PPC32"         = 4
		"PPC64"         = 8
		"QPX"           = 16
		"SPARC32"       = 4
		"SPARC64"       = 8
		"V9"            = 16
	}

	New-Variable -Option Constant -Name ks_opt_value -Value @{
		"Intel" = 1
		"ATT"   = 2
		"NASM"  = 4
		# unsupported -> keystone.h
		"MASM"  = 8
		"GAS"   = 16
	}

	# Asm Handle
	$AsmHandle = [IntPtr]::Zero

	# Initialize Keystone with ks_open()
	# Add a try/catch here to handle missing DLL
	try {
		$CallResult = [Keystone]::ks_open($ks_arch[$Architecture],$ks_mode[$Mode],[ref]$AsmHandle)
	} catch {
		if ($Error[0].FullyQualifiedErrorId -eq "DllNotFoundException") {
			echo "`n[!] Missing Keystone DLL"
		} else {
			echo "`n[!] Exception: $($Error[0].FullyQualifiedErrorId)"
		}
		echo "[>] Quitting..`n"
		Return
	}
	if ($CallResult -ne "KS_ERR_OK") {
		if ($CallResult -eq "KS_ERR_MODE"){
			echo "`n[!] Invalid Architecture/Mode combination"
			echo "[>] Quitting..`n"
		} else {
			echo "`n[!] cs_open error: $CallResult"
			echo "[>] Quitting..`n"
		}
		Return
	}

	# Only one ks_opt_type -> KS_OPT_SYNTAX = 1
	$CallResult = [Keystone]::ks_option($AsmHandle, 1, $ks_opt_value[$Syntax])
	if ($CallResult -ne "KS_ERR_OK") {
		echo "`n[!] ks_option error: $CallResult"
		echo "[>] Quitting..`n"
		$CallResult = [Keystone]::ks_close($AsmHandle)
		Return
	}

	# Result variables
	$Encoded = [IntPtr]::Zero
	[int]$Encoded_size = 0
	[int]$Stat_count = 0

	# Assemble instructions
	$CallResult = [Keystone]::ks_asm($AsmHandle, $Code, 0, [ref]$Encoded, [ref]$Encoded_size, [ref]$stat_count)

	if ($CallResult -ne 0) {
		echo "`n[!] ks_asm error: $([Keystone]::ks_errno($AsmHandle))"
		echo "[>] Quitting..`n"
		$CallResult = [Keystone]::ks_close($AsmHandle)
		Return
	} else {
		$BufferOffset = $Encoded.ToInt64()

		if ($Encoded_size -gt 0) {
			# PS/C# hex array
			$PSArray = @()
			# C-style hex array
			$CArray = @()
			# Raw hex array
			$RawArray = @()
			for ($i=0; $i -lt $Encoded_size; $i++) {
				$PSArray += echo "0x$("{0:X2}" -f $([Runtime.InteropServices.Marshal]::ReadByte($BufferOffset)))"
				$CArray += echo "\x$("{0:X2}" -f $([Runtime.InteropServices.Marshal]::ReadByte($BufferOffset)))"
				$RawArray += echo "$("{0:X2}" -f $([Runtime.InteropServices.Marshal]::ReadByte($BufferOffset)))"
				$BufferOffset = $BufferOffset+1
			}
			# Result Object
			$HashTable = @{
				Bytes = $Encoded_size
				Instructions = $stat_count
				PSArray = $PSArray
				CArray = $CArray
				RawArray = $RawArray
			}
			New-Object PSObject -Property $HashTable |Select-Object Bytes,Instructions,PSArray,CArray,RawArray

			# Clean up!
			[Keystone]::ks_free($Encoded)
			$CallResult = [Keystone]::ks_close($AsmHandle)
		} else {
			echo "`n[!] No bytes assembled"
			echo "[>] Quitting..`n"
			$CallResult = [Keystone]::ks_close($AsmHandle)
			Return
		}
	}

}