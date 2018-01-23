.686
.MMX
.XMM
.x64

option casemap : none
option win64 : 11
option frame : auto
option stackbase : rsp

_WIN64 EQU 1
WINVER equ 0501h


include KSExample_x64.inc

.CODE

WinMainCRTStartup proc FRAME
    invoke GetModuleHandle, NULL
    mov hInstance, rax
    invoke GetCommandLine
    mov CommandLine, rax
    Invoke InitCommonControls
    mov icc.dwSize, sizeof INITCOMMONCONTROLSEX
    mov icc.dwICC, ICC_COOL_CLASSES or ICC_STANDARD_CLASSES or ICC_WIN95_CLASSES
    Invoke InitCommonControlsEx, offset icc
    invoke WinMain, hInstance, NULL, CommandLine, SW_SHOWDEFAULT
    invoke ExitProcess, eax
    ret
WinMainCRTStartup endp

;-------------------------------------------------------------------------------------
; WinMain
;-------------------------------------------------------------------------------------
WinMain proc FRAME hInst:HINSTANCE, hPrev:HINSTANCE, CmdLine:LPSTR, iShow:DWORD
    LOCAL msg:MSG
    LOCAL wcex:WNDCLASSEX
    
    mov wcex.cbSize, sizeof WNDCLASSEX
    mov wcex.style, CS_HREDRAW or CS_VREDRAW
    lea rax, WndProc
    mov wcex.lpfnWndProc, rax
    mov wcex.cbClsExtra, 0
    mov wcex.cbWndExtra, DLGWINDOWEXTRA
    mov rax, hInst
    mov wcex.hInstance, rax
    mov wcex.hbrBackground, COLOR_WINDOW+1
    mov wcex.lpszMenuName, NULL 
    lea rax, ClassName
    mov wcex.lpszClassName, rax
    ;invoke LoadIcon, NULL, IDI_APPLICATION
    Invoke LoadIcon, hInst, ICO_MAIN ; resource icon for main application icon
    mov hIcoMain, rax ; main application icon   
    mov wcex.hIcon, rax
    mov wcex.hIconSm, rax
    invoke LoadCursor, NULL, IDC_ARROW
    mov wcex.hCursor, rax
    invoke RegisterClassEx, addr wcex
    
    ;invoke CreateWindowEx, 0, addr ClassName, addr szAppName, WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, NULL, NULL, hInstance, NULL
    Invoke CreateDialogParam, hInstance, IDD_DIALOG, 0, Addr WndProc, 0
    mov hWnd, rax
    
    invoke ShowWindow, hWnd, SW_SHOWNORMAL
    invoke UpdateWindow, hWnd
    
    .while (TRUE)
        invoke GetMessage, addr msg, NULL, 0, 0
        .break .if (!rax)       
        
        invoke TranslateMessage, addr msg
        invoke DispatchMessage, addr msg
    .endw
    
    mov rax, msg.wParam
    ret 
WinMain endp

;-------------------------------------------------------------------------------------
; WndProc - Main Window Message Loop
;-------------------------------------------------------------------------------------
WndProc proc FRAME hWin:HWND, uMsg:UINT, wParam:WPARAM, lParam:LPARAM
    
    mov eax, uMsg
    .IF eax == WM_INITDIALOG
        ; Init Stuff Here
        
        Invoke GetSysColorBrush, COLOR_WINDOW
        mov hWhiteBrush, eax        
        
        Invoke GetDlgItem, hWin, IDC_TxtAsmToEncode
        mov hTxtAsmToEncode, rax

        Invoke GetDlgItem, hWin, IDC_TxtEncodedBytes
        mov hTxtEncodedBytes, rax
        
        Invoke SetWindowText, hTxtAsmToEncode, Addr szCODEInitial
        
    .ELSEIF eax == WM_COMMAND
        mov rax, wParam
        .IF rax == IDM_FILE_EXIT || rax == IDC_BtnExit
            Invoke SendMessage, hWin, WM_CLOSE, 0, 0
            
        .ELSEIF rax == IDM_HELP_ABOUT
            Invoke ShellAbout, hWin, Addr AppName, Addr AboutMsg, NULL
        
        .ELSEIF rax == IDC_BtnEncode
            Invoke DoEncode, hWin
            
        .ENDIF

    .ELSEIF eax == WM_CTLCOLORSTATIC
        mov eax, hWhiteBrush
        ret

    .ELSEIF eax == WM_CLOSE
        Invoke DestroyWindow, hWin
        
    .ELSEIF eax == WM_DESTROY
        Invoke PostQuitMessage, NULL
        
    .ELSE
        invoke DefWindowProc, rcx, edx, r8, r9
        ret
    .ENDIF
    xor rax, rax
    ret
WndProc endp

;-------------------------------------------------------------------------------------
; DoEncode - Keystone encode assembler in text box to bytes
;-------------------------------------------------------------------------------------
DoEncode PROC FRAME USES RBX hWin:QWORD
    LOCAL i:QWORD
    
    ; Fetch text user typed (or default code string)
    Invoke GetWindowText, hTxtAsmToEncode, Addr szCODEBuffer, SIZEOF szCODEBuffer
    .IF rax == 0
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
    mov ks_err, rax
    .IF rax != KS_ERR_OK
        Invoke MessageBox, 0, Addr szKSOpenFail, Addr szKSError, MB_OK
        ret 
    .ENDIF

    ; Encode assembler code to bytes
    Invoke ks_asm, ks_engine, Addr szCODEBuffer, 0, Addr Encode, Addr EncodeSize, Addr Count
    mov ks_err, rax
    .IF rax != KS_ERR_OK
        Invoke MessageBox, 0, Addr szKSAsmFail, Addr szKSError, MB_OK
        ret
    .ELSE
        
        ; loop through encoding, fetch each byte and add to our final output string
        mov i, 0
        mov rax, 0
        .WHILE rax < EncodeSize
        
            mov rbx, Encode
            add rbx, i
            movzx rax, byte ptr [rbx]
            
            Invoke wsprintf, Addr szOutput, Addr szFmt, rax
            Invoke lstrcat, Addr szFinalOutput, Addr szOutput
            
            inc i
            mov rax, i
        .ENDW
    .ENDIF
    
    ; Clean up stuff
    Invoke ks_free, Encode
    Invoke ks_close, ks_engine

    ; Show encoded bytes to user
    Invoke SetWindowText, hTxtEncodedBytes, Addr szFinalOutput

    ret
DoEncode endp

end WinMainCRTStartup