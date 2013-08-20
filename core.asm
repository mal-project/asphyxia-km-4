; 6/13/2009 ------------------------------------------------------------
; +------------u  n  t  i  l----r  e  a  c  h----v  o  i  d------------¦
; ¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦
; ¦            ¦¦        _   ¦¦            ¦¦           ¯¦¦       ¯    ¦
; ¦  ________  ¦¦___      ¯¯¯¦¦  ________  ¦¦            ¦¦¦_        ¯¦¦
; ¦     _      ¦¦   ¯        ¦¦           _¦¦        _   ¦¦   _        ¦
; ¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦
; a         s         p         h        y         x         i         a
;
; ¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦

.code
;-----------------------------------------------------------------------
; validates a registration lpszRegistration, returns TRUE if registration is
; valid and FALSE if its not.
;
; A valid registration must fullfil:
;       SHA256(szname).part1 = x mod p1; SHA256(szname).part2 = x mod p2
;
; Registration has the following format:
;                          Q, "-", X
;
; Being Q bob's sharing key from g^b mod p, the "Activation code", P,
; from g^a mod p, g any natural > 1, p a prime and a a random number.
; Q holds the key for decryption of X. Such as Q^a mod p == P^b mod p
; ie: (g^b)^a mod p == (g^a)^b mod p == g^ba mod p == g^ab mod p
;
; X is the solution to the system of congruences and is encrypted with key 
; T=(P^b mod p)
    validate_registration   proc    hWnd:HWND, lpszName:dword, dwLen:dword, lpszRegistration:dword
        local   S:hBIG, _return:dword, bigx[500]:byte
        pushad
        ; 1 - First part of registration is based on Diffie-Hellman key exchange
        ; thus we have a secret key a (from GetTickCount), a generator g and a prime p
        ;
        ; We'll exchange a key to perform a symetric encryption but without reveling actual keys.
        ; To achive this each part of the interchange, lets say alice and bob, will
        ; choose each a secret key, a and b. They'll take p as a prime and g as any natural number > 1
        ; and not a multiple of p.
        ;
        ; Next alice and bob will create Shared Keys, P and Q respectly, by doing:
        ;       P = g^a mod p   ; P is alice's sharing key
        ;       Q = g^b mod p   ; Q is bob's sharing key
        ;
        ; And then alice send to bob her sharing key, P; and bob
        ; do it too with his sharing key Q.
        ;
        ; And finally they compute their session key by doing:
        ;       S = Q^a mod p   ; (g^b)^a mod p, alice takes bob's sharing key
        ;       T = P^b mod p   ; (g^a)^b mod p, bob take alice's sharing key
        ;
        ; Resulting in a common secret, to perform symetric encryption:
        ;                       T == S
        ; hint?: (g^a)^b mod p == (g^b)^a mod p == g^ab mod p == g^ba mod p
        
        ; we'll take bob's sharing key Q from registration to perform Q^a mod p = S (decryption key)
        invoke  registration_get_q, lpszRegistration
        invoke  diffiehellman_calculate_s, lpszRegistration, diffiehellman.secret, diffiehellman.prime
        mov     S, eax
        
        ; Decrypting X with S as key
        mov     ecx, [eax]
        imul    ecx, 4
        add     eax, 4
        mov     edx, eax
        invoke  registration_decrypt_x, lpszRegistration, edx, ecx, addr bigx

        ; Oops
        and     dword ptr bigx, 0FFh

        ; 2 - Second part is based on Chinese Remainder Theorem. You've to solve
        ; the system of congruences:
        ;   X = m1 mod p1, X = m2 mod p2, X = m3 mod p3
        ;
        ; Being mi hash parts and pi primes.
        ;
        ; Then its: M = P1 * P2 * P3
        ; M1 = M/P1
        ; M2 = M/P2
        ; M3 = M/P3
        ;
        ; The euclides algorithm give us (r,s) such as r*mi + si*Mi = 1, and ei = si*Mi = Xi
        ; Finally X = m1 * X1 + m2 * X2 + m3 * X3
        ;
        ; X is the solution to the system

        invoke  crt_validate, addr bigx, lpszName, dwLen
        mov     _return, eax

        invoke  big_destroy, S
        
        popad
        
        mov     eax, _return
        ret
    
    validate_registration   endp

;-----------------------------------------------------------------------
; initalizes Diffie-Hellman key exchange and display basic registration
; information, creates registration thread
    initialize  proc    hWnd:HWND
        local   dwlen:dword
        local   szname[100], Pstr[10]:byte  ; activation code
        pushad

        ; Generating and displaying alice sharing key (P=g^a mod p) in "Activation" field
        invoke  diffiehellman_init, addr diffiehellman
        xchg    edx, eax
        invoke  big_cotstr, edx, addr Pstr
        invoke  SendDlgItemMessage, hWnd, IDE_ACTIVATION, WM_SETTEXT, 0, addr Pstr

        ; Fetching and displaying user name in field "Name"
        mov     dwlen, MAX_NAME_LENGTH
        invoke  GetUserName, addr szname, addr dwlen
        invoke  SendDlgItemMessage, hWnd, IDE_NAME, WM_SETTEXT, 0, addr szname
        
        ; Setting up object to activate the thread below
        invoke  CreateEvent, 0, 0, 0, 0
        mov     hEvent, eax

        ; Creates registration basic check thread
        invoke  CreateThread, NULL, NULL, addr registration, hWnd, NULL, NULL

        popad
        ret
    initialize  endp

;-----------------------------------------------------------------------
; Frees memory
    deinitialize    proc
        
        invoke  diffiehellman_destroy, addr diffiehellman

        ret
    deinitialize    endp

;-----------------------------------------------------------------------
    include     core\misc.inc
    include     core\diffiehellman\core.inc
    include     core\crt\core.inc

;-----------------------------------------------------------------------
