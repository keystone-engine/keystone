include windows.inc
include CommCtrl.inc
include shellapi.inc

includelib user32.lib
includelib kernel32.lib
includelib gdi32.lib
includelib comctl32.lib
includelib shell32.lib


include keystone_x64.inc
includelib keystone_x64.lib

;-----------------------------------------------------------------------------------------
; KSExample_x64 Prototypes
;-----------------------------------------------------------------------------------------
DoEncode                PROTO :QWORD

.CONST
;-----------------------------------------------------------------------------------------
; KSExample_x64 Constants
;-----------------------------------------------------------------------------------------
ICO_MAIN                equ 101

; Main Dialog
;KSExample_x64.dlg
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
; KSExample_x64 Initialized Data
;-----------------------------------------------------------------------------------------
align 01
szClass                 db 'Win64class', 0
szAppName               db 'First Window', 0

ClassName               DB 'DLGCLASS',0
AppName                 DB 'LTLI Dialog',0
AboutMsg                DB 'www.LetTheLight.in',13,10,'Copyright © fearless 2017',0

szNull                  DB 0,0
szFmt                   DB '%02X ',0
szCODEBuffer            DB 256 DUP (0)
szCODEInitial           DB 'INC ecx; DEC edx',0
szOutput                DB 256 DUP (0)
szFinalOutput           DB 256 DUP (0)

ks_engine               DQ 0
Encode                  DQ 0
EncodeSize              DQ 0
Count                   DQ 0
ks_err                  DQ 0

szKSError               DB 'Keystone Error',0
szKSCodeEmpty           DB 'Please enter some assembly code to encode.',0
szKSOpenFail            DB 'ERROR: failed on ks_open',0
szKSAsmFail             DB 'ERROR: ks_asm failed',0

.DATA?
;-----------------------------------------------------------------------------------------
; KSExample_x64 Uninitialized Data
;-----------------------------------------------------------------------------------------
align 08
icc                     INITCOMMONCONTROLSEX <>
hInstance               HINSTANCE ?
CommandLine             LPSTR ?
hWnd                    HWND ?
hIcoMain                DQ ?
hWhiteBrush             DD ?
hTxtAsmToEncode         DQ ?
hTxtEncodedBytes        DQ ?