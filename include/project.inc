;-----------------------------------------------------------------------
include     includes.inc
include     core\diffiehellman\data.inc
include     core\crt\data.inc

;-----------------------------------------------------------------------
HideDlgProc     proto   :HWND,:UINT,:WPARAM,:LPARAM
HelpDlgProc     proto   :HWND,:UINT,:WPARAM,:LPARAM
MainDlgProc     proto   :HWND,:UINT,:WPARAM,:LPARAM

;-----------------------------------------------------------------------
initialize          proto   :HWND
registration        proto   :dword
validate_format     proto   :dword
registration_get_q  proto   :dword
get_str_len         proto   :dword
base256             proto   :dword, :dword
validate_registration   proto   :HWND, :dword, :dword, :dword
registration_decrypt_x  proto   :dword, :dword, :dword, :dword

;-----------------------------------------------------------------------
MIN_SERIAL_LENGTH   equ 80
MIN_NAME_LENGTH     equ 5
MAX_NAME_LENGTH     equ 64

WM_DEFEATED equ WM_USER + 1337

;-----------------------------------------------------------------------
CRLF    equ 13, 10
TAB     equ 9

;-----------------------------------------------------------------------
.const   
    szTitle     db "Congratulations!", 0
    szMessage   db "You just defeated this protection.", CRLF
                db "Now you should share your knowledge with others.", CRLF
                db "Make a tutorial on how you reverse it.", 0

;-----------------------------------------------------------------------
.data

;-----------------------------------------------------------------------    
.data?
    hInst   HINSTANCE   ?
    hEvent  HANDLE      ?

    szName  db  MAX_NAME_LENGTH+1 dup(?)
    szRegistration    db 1000 dup(?)

;-----------------------------------------------------------------------
