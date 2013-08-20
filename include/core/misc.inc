;-----------------------------------------------------------------------
.code
   
;-----------------------------------------------------------------------
; Convert X to base256 and decrypt it with key Q^a mod P
    registration_decrypt_x  proc    lpszRegistration, lpkey, dwlen, lpout:dword
        local   _length:dword
        local   buffer[500]:byte
        
        pushad
        mov     esi, lpszRegistration
        .repeat
            inc     esi
        .until  byte ptr [esi] == 0
        inc     esi
        
        invoke  get_str_len, esi
        mov     ecx, 2
        xor     edx, edx
        idiv    ecx
        mov     _length, eax

        invoke  base256, esi, addr buffer

        invoke  blowfish_init, lpkey, dwlen
        invoke  blowfish_decrypt, addr buffer, _length, lpout

        popad
        ret
    registration_decrypt_x  endp

;-----------------------------------------------------------------------
; Determines if a given string has the "X-X" format, being X a series
; of upcase A-F, 0-9 chars
; in : lpszStr a pointer to a zero terminated string to evaluate
; out: FALSE if the string have a non valid characters or hasnt
;      any "-" character or have more than one "-" character
;      >0 if the string has a correct format
    validate_format proc   lpszStr:dword
        local   _return, _dwslashes:dword
        pushad
        mov     _dwslashes, 0
        mov     esi, lpszStr

        .while  byte ptr [esi] != 0
            .if byte ptr [esi] >= 'A' && byte ptr [esi] <= 'F' || byte ptr [esi] >= '0' && byte ptr [esi] <= '9'
           
            .elseif  byte ptr [esi] == '-'
                inc     _dwslashes
            
            .else
                .break
            .endif
            
            inc     esi
        
        .endw

        .if     byte ptr [esi] == 0 && _dwslashes == 1
            sub     esi, lpszStr
            mov     _return, esi
        
        .else
            mov     _return, FALSE

        .endif

        popad
        mov     eax, _return
        ret
    validate_format endp

;-----------------------------------------------------------------------
; Runs over registration string to divide (by a null) bob's sharing key
; (Diffie-Hellman key exchage protocol) and X, which is the solution
; to the system of congruences (Chinese Remainder Theorem)
    registration_get_q  proc    lpszRegistration:dword
        pushad
        mov     esi, lpszRegistration
        .while  byte ptr [esi] != '-'
            inc     esi
        .endw
        
        xor     eax, eax
        xchg    esi, edi
        stosb
        
        popad
        ret
    registration_get_q   endp

;-----------------------------------------------------------------------
; Thread to check on entering any character in fields "Name" and "Registration"
; determines basic conditions to perform a registration check.
; On entering data into IDE_NAME or IDE_SERIAL the object hEvent is signaled and
; this thread evaluates serial length and its format, and name length.
; If these basic conditions meets then the registration routine is called
    registration  proc    hWnd:HWND

        .while  (1)
            invoke  WaitForSingleObject, hEvent, -1
            
            invoke  SendDlgItemMessage, hWnd, IDE_REGISTRATION, WM_GETTEXT, sizeof szRegistration, addr szRegistration            
            .if     eax >= MIN_SERIAL_LENGTH
                
                invoke  validate_format, addr szRegistration
                .if     eax

                    invoke  SendDlgItemMessage, hWnd, IDE_NAME, WM_GETTEXT, sizeof szName, addr szName

                    .if     eax >= MIN_NAME_LENGTH && eax <= MAX_NAME_LENGTH

                        invoke  validate_registration, hWnd, addr szName, eax, addr szRegistration

                        .if     eax == TRUE
                            invoke  PostMessage, hWnd, WM_DEFEATED, 0, 0
                        
                        .endif
                        
                    .endif
            
                .endif
            
            .endif
        
        .endw

        ret
    registration endp
    
;-----------------------------------------------------------------------
    include     core\hexstr2dword.inc
    
    base256 proc    lphexstr, lpout:dword
        mov     esi, lphexstr
        mov     edi, lpout
        
        @@:
            invoke  hexstr2dword
            stosd
            lodsd
            lodsd
            cmp     dword ptr [esi], 0
            jnz     @B
        
        ret
    base256 endp

;-----------------------------------------------------------------------
    get_str_len proc uses esi, lpstr:dword
        mov     esi, lpstr
        .repeat
            lodsb
        .until  !al
        sub     esi, lpstr
        dec     esi
        xchg    eax, esi
        ret
    get_str_len endp

;-----------------------------------------------------------------------
