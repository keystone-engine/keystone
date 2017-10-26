include windows.inc
include user32.inc
include kernel32.inc
include gdi32.inc
include shell32.inc
include comctl32.inc
include comdlg32.inc
include masm32.inc

includelib user32.lib
includelib kernel32.lib
includelib gdi32.lib
includelib shell32.lib
includelib comctl32.lib
includelib comdlg32.lib
includelib masm32.lib

include keystone_x86.inc
includelib keystone_x86.lib

;-----------------------------------------------------------------------------------------
; KSExample_x86 Prototypes
;-----------------------------------------------------------------------------------------
WinMain                 PROTO :DWORD,:DWORD,:DWORD,:DWORD
WndProc                 PROTO :DWORD,:DWORD,:DWORD,:DWORD
DoEncode                PROTO :DWORD

.CONST
;-----------------------------------------------------------------------------------------
; KSExample_x86 Constants
;-----------------------------------------------------------------------------------------
ICO_MAIN                equ 101

; Main Dialog
;KSExample_x86.dlg
IDD_DIALOG              equ 1000
IDC_TxtAsmToEncode      equ 1001
IDC_TxtEncodedBytes     equ 1002
IDC_LblAsmToEncode      equ 1003
IDC_LblEncodedBytes     equ 1004
IDC_BtnExit             equ 1005
IDC_BtnEncode           equ 1006

; Main Menu 
IDM_MENU                EQU 10000
IDM_FILE_EXIT           EQU 10001
IDM_HELP_ABOUT          EQU 10101

.DATA
;-----------------------------------------------------------------------------------------
; KSExample_x86 Initialized Data
;-----------------------------------------------------------------------------------------
ClassName               DB 'DLGCLASS',0
AppName                 DB 'LTLI Dialog',0
AboutMsg                DB 'www.LetTheLight.in',13,10,'Copyright © fearless 2014',0

szNull                  DB 0,0
szFmt                   DB '%02X ',0
szCODEBuffer            DB 256 DUP (0)
szCODEInitial           DB 'INC ecx; DEC edx',0
szOutput                DB 256 DUP (0)
szFinalOutput           DB 256 DUP (0)

ks_engine               DD 0
Address                 DQ 0 ; Note has to be QWORD sized as a parameter for ks_asm
Encode                  DD 0
EncodeSize              DD 0
Count                   DD 0
ks_err                  DD 0

szKSError               DB 'Keystone Error',0
szKSCodeEmpty           DB 'Please enter some assembly code to encode.',0
szKSOpenFail            DB 'ERROR: failed on ks_open',0
szKSAsmFail             DB 'ERROR: ks_asm failed',0

.DATA?
;-----------------------------------------------------------------------------------------
; KSExample_x86 Uninitialized Data
;-----------------------------------------------------------------------------------------
icc                     INITCOMMONCONTROLSEX <>
hInstance               DD ?
CommandLine             DD ?
hWnd                    DD ?
hIcoMain                DD ?
hWhiteBrush             DD ?
hTxtAsmToEncode         DD ?
hTxtEncodedBytes        DD ?