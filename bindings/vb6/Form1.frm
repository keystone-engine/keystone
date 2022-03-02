VERSION 5.00
Object = "{831FDD16-0C5C-11D2-A9FC-0000F8754DA1}#2.0#0"; "MSCOMCTL.OCX"
Begin VB.Form Form1 
   Caption         =   "Keystone Assembler Engine VB6 Bindings - Contributed by FireEye FLARE team"
   ClientHeight    =   4680
   ClientLeft      =   60
   ClientTop       =   345
   ClientWidth     =   10860
   LinkTopic       =   "Form1"
   ScaleHeight     =   4680
   ScaleWidth      =   10860
   StartUpPosition =   2  'CenterScreen
   Begin VB.CommandButton Command1 
      Caption         =   "Copy"
      Height          =   375
      Left            =   4680
      TabIndex        =   1
      Top             =   4200
      Width           =   1695
   End
   Begin MSComctlLib.ListView lv 
      Height          =   3975
      Left            =   120
      TabIndex        =   0
      Top             =   120
      Width           =   10695
      _ExtentX        =   18865
      _ExtentY        =   7011
      View            =   3
      LabelEdit       =   1
      LabelWrap       =   -1  'True
      HideSelection   =   -1  'True
      FullRowSelect   =   -1  'True
      GridLines       =   -1  'True
      _Version        =   393217
      ForeColor       =   -2147483640
      BackColor       =   -2147483643
      BorderStyle     =   1
      Appearance      =   1
      NumItems        =   3
      BeginProperty ColumnHeader(1) {BDD1F052-858B-11D1-B16A-00C0F0283628} 
         Text            =   "arch"
         Object.Width           =   5292
      EndProperty
      BeginProperty ColumnHeader(2) {BDD1F052-858B-11D1-B16A-00C0F0283628} 
         SubItemIndex    =   1
         Text            =   "asm"
         Object.Width           =   5292
      EndProperty
      BeginProperty ColumnHeader(3) {BDD1F052-858B-11D1-B16A-00C0F0283628} 
         SubItemIndex    =   2
         Text            =   "bytes"
         Object.Width           =   14111
      EndProperty
   End
End
Attribute VB_Name = "Form1"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = False
Option Explicit

'Keystone Assembly Engine bindings for VB6
'Contributed by FireEye FLARE Team
'Author:  David Zimmer <david.zimmer@fireeye.com>, <dzzie@yahoo.com>
'License: Apache 2.0
'Copyright: FireEye 2017

'NOTE: the VB code was built and tested against the latest binary release: Keystone 0.9.1
'      I will enabled the symbol resolver once it makes it into the stable release

Private Sub Form_Load()
    
    Const base As Long = 0 '&H1000
    
    initDll
    If hLib <> 0 Then Me.Caption = Me.Caption & " - loaded KeyStone v" & version
    
    'MsgBox err2str(KS_ERR_ASM_SYMBOL_MISSING)
    
    ' X86
    'AddResult test_ks(KS_ARCH_X86, KS_MODE_32, "jmp 0x2000; nop; nop;", 0, base)
    AddResult test_ks(KS_ARCH_X86, KS_MODE_16, "add eax, ecx", 0, base)
    AddResult test_ks(KS_ARCH_X86, KS_MODE_32, "add eax, ecx", 0, base)
    AddResult test_ks(KS_ARCH_X86, KS_MODE_64, "add rax, rcx", 0, base)
    AddResult test_ks(KS_ARCH_X86, KS_MODE_32, "add %ecx, %eax", KS_OPT_SYNTAX_ATT, base)
    AddResult test_ks(KS_ARCH_X86, KS_MODE_64, "add %rcx, %rax", KS_OPT_SYNTAX_ATT, base)

    ' ARM
    AddResult test_ks(KS_ARCH_ARM, KS_MODE_ARM, "sub r1, r2, r5", 0, base)
    AddResult test_ks(KS_ARCH_ARM, KS_MODE_ARM + KS_MODE_BIG_ENDIAN, "sub r1, r2, r5", 0, base)
    AddResult test_ks(KS_ARCH_ARM, KS_MODE_THUMB, "movs r4, #0xf0", 0, base)
    AddResult test_ks(KS_ARCH_ARM, KS_MODE_THUMB + KS_MODE_BIG_ENDIAN, "movs r4, #0xf0", 0, base)

    ' ARM64
    AddResult test_ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, "ldr w1, [sp, #0x8]", 0, base)

    ' Hexagon
    AddResult test_ks(KS_ARCH_HEXAGON, KS_MODE_BIG_ENDIAN, "v23.w=vavg(v11.w,v2.w):rnd", 0, base)

    ' Mips
    AddResult test_ks(KS_ARCH_MIPS, KS_MODE_MIPS32, "and $9, $6, $7", 0)
    AddResult test_ks(KS_ARCH_MIPS, KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN, "and $9, $6, $7", 0, base)
    AddResult test_ks(KS_ARCH_MIPS, KS_MODE_MIPS64, "and $9, $6, $7", 0)
    AddResult test_ks(KS_ARCH_MIPS, KS_MODE_MIPS64 + KS_MODE_BIG_ENDIAN, "and $9, $6, $7", 0, base)

    ' PowerPC
    AddResult test_ks(KS_ARCH_PPC, KS_MODE_PPC32 + KS_MODE_BIG_ENDIAN, "add 1, 2, 3", 0, base)
    AddResult test_ks(KS_ARCH_PPC, KS_MODE_PPC64, "add 1, 2, 3", 0)
    AddResult test_ks(KS_ARCH_PPC, KS_MODE_PPC64 + KS_MODE_BIG_ENDIAN, "add 1, 2, 3", 0, base)

    ' Sparc
    AddResult test_ks(KS_ARCH_SPARC, KS_MODE_SPARC32 + KS_MODE_LITTLE_ENDIAN, "add %g1, %g2, %g3", 0, base)
    AddResult test_ks(KS_ARCH_SPARC, KS_MODE_SPARC32 + KS_MODE_BIG_ENDIAN, "add %g1, %g2, %g3", 0, base)

    ' SystemZ
    AddResult test_ks(KS_ARCH_SYSTEMZ, KS_MODE_BIG_ENDIAN, "a %r0, 4095(%r15,%r1)", 0, base)
    
    ' symbol resolver test (will enable once in stable release binaries not tested yet)
    'AddResult test_ks(KS_ARCH_X86, KS_MODE_32, "jmp _l1; nop", 0, , base, True)
    
End Sub


Public Function test_ks(arch As ks_arch, mode As ks_mode, assembly As String, Optional syntax As ks_opt_type = 0, Optional base As Long = 0, Optional withResolver As Boolean = False) As CAsmResult
    
    Dim r As New CAsmResult
    Dim buf As Long, size As Long, count As Long, b() As Byte
    Dim hKeystone As Long
    Dim address As Currency
    
    Set test_ks = r
    
    If hLib = 0 Then initDll r
    If hLib = 0 Then Exit Function
    
    r.arch = arch
    r.mode = mode
    r.syntax = syntax
    r.source = assembly
    
    If ks_arch_supported(arch) = 0 Then
        r.errMsg = "specified architecture not supported"
        Exit Function
    End If
    
    r.lastErr = ks_open(arch, mode, hKeystone)
    If r.lastErr <> KS_ERR_OK Then
        r.errMsg = err2str(r.lastErr)
        Exit Function
    End If

    'If withResolver Then setResolver hKeystone, AddressOf vbSymResolver
    If syntax <> 0 Then Call ks_option(hKeystone, KS_OPT_SYNTAX, syntax)
    
    address = lng2Cur(base)
    r.lastErr = ks_asm(hKeystone, assembly, address, buf, size, count)
    
    If r.lastErr = KS_ERR_OK Then
        ReDim b(size - 1)
        CopyMemory ByVal VarPtr(b(0)), ByVal buf, size
        ks_free buf
        r.result = b()
        r.count = count
        r.size = size
    End If
    
    ks_close hKeystone
    
End Function

Function AddResult(r As CAsmResult)
    
    Dim li As ListItem
    
    Set li = lv.ListItems.Add(, , ks_arch2str(r.arch))
    li.SubItems(1) = r.source
    If r.hadErr Then
        li.SubItems(2) = "Error: " & r.errMsg
    Else
        li.SubItems(2) = b2Str(r.result)
    End If
    Set li.Tag = r
    
End Function

Private Sub Command1_Click()
    Clipboard.Clear
    Clipboard.SetText GetAllElements(lv)
End Sub

