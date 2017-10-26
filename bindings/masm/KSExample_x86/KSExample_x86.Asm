.686
.MMX
.XMM
.model flat,stdcall
option casemap:none
include \masm32\macros\macros.asm

;DEBUG32 EQU 1

IFDEF DEBUG32
    PRESERVEXMMREGS equ 1
    includelib M:\Masm32\lib\Debug32.lib
    DBG32LIB equ 1
    DEBUGEXE textequ <'M:\Masm32\DbgWin.exe'>
    include M:\Masm32\include\debug32.inc
ENDIF

include KSExample_x86.inc

.code

start:

    Invoke GetModuleHandle,NULL
    mov hInstance, eax
    Invoke GetCommandLine
    mov CommandLine, eax
    Invoke InitCommonControls
    mov icc.dwSize, sizeof INITCOMMONCONTROLSEX
    mov icc.dwICC, ICC_COOL_CLASSES or ICC_STANDARD_CLASSES or ICC_WIN95_CLASSES
    Invoke InitCommonControlsEx, offset icc
    
    Invoke WinMain, hInstance, NULL, CommandLine, SW_SHOWDEFAULT
    Invoke ExitProcess, eax

;-------------------------------------------------------------------------------------
; WinMain
;-------------------------------------------------------------------------------------
WinMain proc hInst:HINSTANCE,hPrevInst:HINSTANCE,CmdLine:LPSTR,CmdShow:DWORD
    LOCAL   wc:WNDCLASSEX
    LOCAL   msg:MSG

    mov     wc.cbSize, sizeof WNDCLASSEX
    mov     wc.style, CS_HREDRAW or CS_VREDRAW
    mov     wc.lpfnWndProc, offset WndProc
    mov     wc.cbClsExtra, NULL
    mov     wc.cbWndExtra, DLGWINDOWEXTRA
    push    hInst
    pop     wc.hInstance
    mov     wc.hbrBackground, COLOR_WINDOW+1
    mov     wc.lpszMenuName, NULL
    mov     wc.lpszClassName, offset ClassName
    ;Invoke LoadIcon, NULL, IDI_APPLICATION
    Invoke LoadIcon, hInstance, ICO_MAIN ; resource icon for main application icon
    mov hIcoMain, eax ; main application icon
    mov     wc.hIcon, eax
    mov     wc.hIconSm, eax
    Invoke LoadCursor, NULL, IDC_ARROW
    mov     wc.hCursor,eax
    Invoke RegisterClassEx, addr wc
    Invoke CreateDialogParam, hInstance, IDD_DIALOG, NULL, addr WndProc, NULL
    Invoke ShowWindow, hWnd, SW_SHOWNORMAL
    Invoke UpdateWindow, hWnd
    .WHILE TRUE
        invoke GetMessage, addr msg, NULL, 0, 0
      .BREAK .if !eax
        Invoke TranslateMessage, addr msg
        Invoke DispatchMessage, addr msg
    .ENDW
    mov eax, msg.wParam
    ret
WinMain endp

;-------------------------------------------------------------------------------------
; WndProc - Main Window Message Loop
;-------------------------------------------------------------------------------------
WndProc proc hWin:HWND,uMsg:UINT,wParam:WPARAM,lParam:LPARAM
    
    mov eax, uMsg
    .IF eax == WM_INITDIALOG
        push hWin
        pop hWnd
        ; Init Stuff Here

        Invoke GetSysColorBrush, COLOR_WINDOW
        mov hWhiteBrush, eax        
        
        Invoke GetDlgItem, hWin, IDC_TxtAsmToEncode
        mov hTxtAsmToEncode, eax

        Invoke GetDlgItem, hWin, IDC_TxtEncodedBytes
        mov hTxtEncodedBytes, eax
        
        Invoke SetWindowText, hTxtAsmToEncode, Addr szCODEInitial
        
        
    .ELSEIF eax == WM_COMMAND
        mov eax, wParam
        and eax, 0FFFFh
        .IF eax == IDM_FILE_EXIT || eax == IDC_BtnExit
            Invoke SendMessage,hWin,WM_CLOSE,0,0
            
        .ELSEIF eax == IDM_HELP_ABOUT
            Invoke ShellAbout,hWin,addr AppName,addr AboutMsg,NULL

        .ELSEIF eax == IDC_BtnEncode
            Invoke DoEncode, hWin
            
        .ENDIF

    .ELSEIF eax == WM_CTLCOLORSTATIC
        mov eax, hWhiteBrush
        ret

    .ELSEIF eax == WM_CLOSE
        Invoke DestroyWindow,hWin
        
    .ELSEIF eax == WM_DESTROY
        Invoke PostQuitMessage,NULL
        
    .ELSE
        Invoke DefWindowProc,hWin,uMsg,wParam,lParam
        ret
    .ENDIF
    xor    eax,eax
    ret
WndProc endp

;-------------------------------------------------------------------------------------
; DoEncode - Keystone encode assembler in text box to bytes
;-------------------------------------------------------------------------------------
DoEncode PROC USES EBX hWin:DWORD
    LOCAL i:DWORD
    
    ; Fetch text user typed (or default code string)
    Invoke GetWindowText, hTxtAsmToEncode, Addr szCODEBuffer, SIZEOF szCODEBuffer
    .IF eax == 0
        Invoke MessageBox, 0, Addr szKSCodeEmpty, Addr szKSError, MB_OK
        ret
    .ENDIF
    
    ; Reset some stuff
    Invoke RtlZeroMemory, Addr szFinalOutput, SIZEOF szFinalOutput
    Invoke SetWindowText, hTxtEncodedBytes, Addr szNull

    ; Keystone stuff
    Invoke ks_version, KS_VERSION_MAJOR, KS_VERSION_MINOR
    ; rax contains version
    
    Invoke ks_arch_supported, KS_ARCH_X86
    ; rax contains TRUE if arch is supported by keystone library
    
    Invoke ks_open, KS_ARCH_X86, KS_MODE_32, Addr ks_engine
    mov ks_err, eax
    .IF eax != KS_ERR_OK
        Invoke MessageBox, 0, Addr szKSOpenFail, Addr szKSError, MB_OK
        ret 
    .ENDIF

    ; Note: In x86 asm the ks_asm address parameter (third parameter) is QWORD (uint64_t) size
    
    ; Set address variable by setting low order and high order DWORDs:
    mov dword ptr [Address+0], 00000000h ; High order DWORD of 64bit address
    mov dword ptr [Address+4], 00010000h ; Low order DWORD of 64bit address
    
    ; Encode assembler code to bytes
    Invoke ks_asm, ks_engine, Addr szCODEBuffer, Address, Addr Encode, Addr EncodeSize, Addr Count
    mov ks_err, eax
    .IF eax != KS_ERR_OK
        Invoke MessageBox, 0, Addr szKSAsmFail, Addr szKSError, MB_OK
        ret
    .ELSE
        
        ; loop through encoding, fetch each byte and add to our final output string
        mov i, 0
        mov eax, 0
        .WHILE eax < EncodeSize
        
            mov ebx, Encode
            add ebx, i
            movzx eax, byte ptr [ebx]
            
            Invoke wsprintf, Addr szOutput, Addr szFmt, eax
            Invoke lstrcat, Addr szFinalOutput, Addr szOutput
            
            inc i
            mov eax, i
        .ENDW
    .ENDIF
    
    ; Clean up stuff
    Invoke ks_free, Encode
    Invoke ks_close, ks_engine

    ; Show encoded bytes to user
    Invoke SetWindowText, hTxtEncodedBytes, Addr szFinalOutput

    ret
DoEncode endp

end start