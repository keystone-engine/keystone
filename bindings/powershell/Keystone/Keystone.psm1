function Get-KeystoneAssembly {
<#
.SYNOPSIS
	Powershell wrapper for Keystone (using inline C#).

.DESCRIPTION
	Author: Ruben Boonen (@FuzzySec)
	License: BSD 3-Clause
	Required Dependencies: None
	Optional Dependencies: None

.PARAMETER Architecture
	Architecture type.

.PARAMETER Mode
	Mode type.

.PARAMETER Code
	Assembly string, use ";" or multi-line variables for instruction separation.

.PARAMETER Syntax
	Syntax for input assembly.

.PARAMETER Version
	Print ASCII version banner.

.EXAMPLE

	# Support for multi-line code blocks
	PS C:\> $Code = @"
	>> sub esp, 200
	>> pop eax
	>> pop ecx
	>> ret
	>> "@
	PS C:\> Get-KeystoneAssembly -Architecture KS_ARCH_X86 -Mode KS_MODE_32 -Code $Code

	Bytes        : 9
	Instructions : 4
	PSArray      : {0x81, 0xEC, 0xC8, 0x00...}
	CArray       : {\x81, \xEC, \xC8, \x00...}
	RawArray     : {81, EC, C8, 00...}

.EXAMPLE

	# Get-KeystoneAssembly emits objects
	PS C:\> $Code = @"
	>> sub esp, 200
	>> pop eax
	>> pop ecx
	>> ret
	>> "@
	PS C:\> $Object = Get-KeystoneAssembly -Architecture KS_ARCH_X86 -Mode KS_MODE_32 -Code $Code
	PS C:\> $Object.RawArray -join ""
	81ECC80000005859C3
	PS C:\> $Object.CArray -join ""
	\x81\xEC\xC8\x00\x00\x00\x58\x59\xC3
	PS C:\> "`$Shellcode = {" + $($Object.PSArray -join ", ") + "}"
	$Shellcode = {0x81, 0xEC, 0xC8, 0x00, 0x00, 0x00, 0x58, 0x59, 0xC3}

#>

	param(
		[Parameter(ParameterSetName='Keystone', Mandatory = $True)]
		[ValidateSet(
			'KS_ARCH_ARM',
			'KS_ARCH_ARM64',
			'KS_ARCH_MIPS',
			'KS_ARCH_X86',
			'KS_ARCH_PPC',
			'KS_ARCH_SPARC',
			'KS_ARCH_SYSTEMZ',
			'KS_ARCH_HEXAGON',
			'KS_ARCH_MAX')
		]
		[String]$Architecture,
		
		[Parameter(ParameterSetName='Keystone', Mandatory = $True)]
		[ValidateSet(
			'KS_MODE_LITTLE_ENDIAN',
			'KS_MODE_BIG_ENDIAN',
			'KS_MODE_ARM',
			'KS_MODE_THUMB',
			'KS_MODE_V8',
			'KS_MODE_MICRO',
			'KS_MODE_MIPS3',
			'KS_MODE_MIPS32R6',
			'KS_MODE_MIPS32',
			'KS_MODE_MIPS64',
			'KS_MODE_16',
			'KS_MODE_32',
			'KS_MODE_64',
			'KS_MODE_PPC32',
			'KS_MODE_PPC64',
			'KS_MODE_QPX',
			'KS_MODE_SPARC32',
			'KS_MODE_SPARC64',
			'KS_MODE_V9')
		]
		[String]$Mode,
		
		[Parameter(ParameterSetName='Keystone', Mandatory = $True)]
		[ValidateNotNullOrEmpty()]
		[string]$Code,
		
		[Parameter(ParameterSetName='Keystone', Mandatory = $False)]
		[ValidateSet(
			'KS_OPT_SYNTAX_INTEL',
			'KS_OPT_SYNTAX_ATT',
			'KS_OPT_SYNTAX_NASM',
			'KS_OPT_SYNTAX_MASM',
			'KS_OPT_SYNTAX_GAS')
		]
		[String]$Syntax = "KS_OPT_SYNTAX_INTEL",
		
		[Parameter(ParameterSetName='Version', Mandatory = $False)]
		[switch]$Version = $null
    )

	# Compatibility for PS v2 / PS v3+
	if(!$PSScriptRoot) {
		$PSScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
	}
	
	# Set the keystone DLL path
	$DllPath = $($PSScriptRoot + '\Lib\Keystone\keystone.dll').Replace('\','\\')

	# Make sure the user didn't forget the DLL
	if (![IO.File]::Exists($DllPath)) {
		echo "`n[!] Missing Keystone DLL"
		echo "[>] Quitting!`n"
		Return
	}

	# Load C# constants
	$ks_err = Select-String "KS_ERR_" $($PSScriptRoot + '\Const\keystone_h.cs') |select -exp line
	$ks_arch = Select-String "KS_ARCH_" $($PSScriptRoot + '\Const\keystone_h.cs') |select -exp line
	$ks_mode = Select-String "KS_MODE_" $($PSScriptRoot + '\Const\keystone_h.cs') |select -exp line
	$ks_opt_value = Select-String "KS_OPT_SYNTAX_" $($PSScriptRoot + '\Const\keystone_h.cs') |select -exp line

	# Inline C# to parse the unmanaged keystone DLL
	Add-Type -TypeDefinition @"
	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	using System.Security.Principal;

	public enum ks_err : int
	{
		$ks_err
	}

	public enum ks_arch : int
	{
		$ks_arch
	}

	public enum ks_mode : int
	{
		$ks_mode
	}

	public enum ks_opt_value : uint
	{
		$ks_opt_value
	}

	public static class Keystone
	{
		[DllImport("$DllPath")]
		public static extern ks_err ks_open(
			ks_arch arch,
			ks_mode mode,
			ref IntPtr handle);

		[DllImport("$DllPath")]
		public static extern ks_err ks_option(
			IntPtr handle,
			int mode,
			ks_opt_value value);

		[DllImport("$DllPath")]
		public static extern int ks_asm(
			IntPtr handle,
			String assembly,
			ulong address,
			ref IntPtr encoding,
			ref uint encoding_size,
			ref uint stat_count);

		[DllImport("$DllPath")]
		public static extern ks_err ks_errno(
			IntPtr handle);

		[DllImport("$DllPath")]
		public static extern ks_err ks_close(
			IntPtr handle);

		[DllImport("$DllPath")]
		public static extern void ks_free(
			IntPtr handle);

		[DllImport("$DllPath")]
		public static extern int ks_version(
			uint major,
			uint minor);
	}
"@

	if ($Version){
		$VerCount = [System.BitConverter]::GetBytes($([Keystone]::ks_version($null,$null)))
		$Banner = @"

                ;#                 
             #########             
           ######""   ;;           
     ###";#### ;##############     
   ##### ### ##""   "## ""######   
   #### ###           ""### "###   
   #### ##               "### "#   
   "### \#               ; ####    
    "### "               ##"####   
   ## \###               ## ####   
   #### "###;           ### ####   
   ######## "#"   ;### ###"#####   
     "#############" ####"/##"     
           "    ;#######           
             "#######"             
                 #                 

     -=[Keystone Engine v$($VerCount[1]).$($VerCount[0])]=-

"@
		# Mmm ASCII version banner!
		$Banner
		Return
	}

	# Asm Handle
	$AsmHandle = [IntPtr]::Zero

	# Initialize Keystone with ks_open()
	$CallResult = [Keystone]::ks_open($Architecture,$Mode,[ref]$AsmHandle)
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
	$CallResult = [Keystone]::ks_option($AsmHandle, 1, $Syntax)
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