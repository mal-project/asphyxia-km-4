;-----------------------------------------------------------------------
.486
.model flat, stdcall
option casemap :none

;-----------------------------------------------------------------------
include     project.inc

;-----------------------------------------------------------------------
.code
    include     core.asm

;-----------------------------------------------------------------------
    MainDlgProc proc    hWnd:HWND, uMsg:UINT, wParam:WPARAM, lParam:LPARAM
        
        switch  uMsg
        
            case    WM_INITDIALOG
                
                invoke  initialize, hWnd
                
            case    WM_COMMAND
                
                mov		eax, wParam
                .if     ax == IDE_NAME || ax == IDE_REGISTRATION
                   
                    shr     eax, 16
                    .if ax == EN_CHANGE
                        invoke  SetEvent, hEvent
                    
                    .endif
    
                .elseif wParam == IDB_CLOSE
    
                    invoke  SendMessage, hWnd, WM_CLOSE, 0, 0
                            
                .elseif wParam == IDB_HELP
                    invoke  DialogBoxParam, hInst, IDD_HELP, hWnd, HelpDlgProc, 0

                .endif

            case    WM_LBUTTONDOWN
                
                invoke  SendMessage, hWnd, WM_NCLBUTTONDOWN, HTCAPTION, 0

            case    WM_DEFEATED
                
                invoke  MessageBox, hWnd, addr szMessage, addr szTitle, MB_ICONINFORMATION

            case    WM_CLOSE || uMsg == WM_RBUTTONUP || uMsg == WM_LBUTTONDBLCLK
                
                invoke  deinitialize
                invoke  EndDialog, hWnd, 0

        endsw
        xor     eax, eax
        ret

    MainDlgProc endp

;-----------------------------------------------------------------------
    HelpDlgProc proc    hWnd:HWND, uMsg:UINT, wParam:WPARAM, lParam:LPARAM
        switch  uMsg
        
            case    WM_INITDIALOG

                invoke  FindResource, hInst, IDR_HELP, RT_RCDATA
                invoke  LoadResource, hInst, eax
                invoke  LockResource, eax
                
                invoke  SendDlgItemMessage, hWnd, IDE_HELP, WM_SETTEXT, 0, eax
            
            case    WM_COMMAND
                 
                .if wParam == IDB_CLOSEHELP
            
                    invoke  SendMessage, hWnd, WM_CLOSE, 0, 0

                .endif
       
            case    WM_LBUTTONDOWN
                
                invoke  SendMessage, hWnd, WM_NCLBUTTONDOWN, HTCAPTION, 0

            case    WM_CLOSE || uMsg == WM_RBUTTONUP || uMsg == WM_LBUTTONDBLCLK

                invoke  EndDialog, hWnd, 0
        endsw

        xor     eax, eax
        ret

    HelpDlgProc endp

;-----------------------------------------------------------------------
    HideDlgProc proc    hWnd:HWND, uMsg:UINT, wParam:WPARAM, lParam:LPARAM
    
        .if     uMsg == WM_INITDIALOG
            invoke  ShowWindow, hWnd, SW_HIDE
            invoke  DialogBoxParam, hInst, IDD_DLG, hWnd, MainDlgProc, 0
            invoke  EndDialog, hWnd, 0
        .endif

        xor     eax, eax
        ret

    HideDlgProc endp

;-----------------------------------------------------------------------
    Start:

        invoke  GetModuleHandle, 0
        mov     hInst,eax
    
        invoke  DialogBoxParam, hInst, IDD_HIDE, 0, HideDlgProc, 0

        invoke  ExitProcess, 0

    end Start
;-----------------------------------------------------------------------
