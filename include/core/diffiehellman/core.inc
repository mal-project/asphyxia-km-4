; Diffie-Hellman Key Exchange
;-----------------------------------------------------------------------
; Calculates the sharing key S from Q^a mod p being Q the bob's sharing key from g^b mod p
; in : lpszQ g^b mod p
;      a random number created at initialization (big number format) being the alice secret
;      p moduli
; out: S result of Q^a mod p
    diffiehellman_calculate_s proc    lpszQ:dword, a:dword, p:dword
        local   Q, S:hBIG
        pushad

        invoke  big_create_array, addr S, 2
        
        invoke  big_cinstr, lpszQ, Q

        ; S = Q^a mod p (S = (g^b)^a mod p == T = (g^a)^b mod p == g^ab == g^ba)
        invoke  big_powmod, Q, a, p, S
        invoke  big_destroy, Q

        popad
        mov     eax, S
        ret
    diffiehellman_calculate_s endp

;-----------------------------------------------------------------------
; generates a secret key in base to GetTickCount()
    diffiehellman_generate_alice_random proc
        local   a:hBIG, arandom:dword
        
        pushad
        invoke  big_create, 0
        mov     a, eax

        invoke  GetTickCount
        mov     arandom, eax
        invoke  big_bytes_to_big, addr arandom, 4, a
        
        popad
        mov     eax, a
        ret
    diffiehellman_generate_alice_random endp

;-----------------------------------------------------------------------
; Generate the sharing key P from g^a mod p
; in: a big alice secret key
;     g generator
;     p prime
; out: P from P=g^a mod p
    diffiehellman_generate_alice_sharing    proc    a:dword, g:dword, p:dword
        local   P:hBIG
        pushad
        invoke  big_create, 0
        mov     P, eax

        ; g^a mod p = P (alice sharing key)
        invoke  big_powmod, g, a, p, P

        popad
        mov     eax, P
        ret    
    diffiehellman_generate_alice_sharing    endp

;-----------------------------------------------------------------------
; Sets the parameters for the Diffie-Hellman protocol, p a prime, g
; any narutal > 1 and not multiple of p
; in : p, g address prime a generator
;      gsize, psize p and g size in bytes
; out: eax = p, edx = g
    diffiehellman_set_params proc    lpg:dword, lpp:dword, gsize:dword, psize:dword
        local   p, g:hBIG
        pushad
        
        invoke  big_create_array, addr g, 2

        invoke  big_bytes_to_big, lpp, psize, p
        invoke  big_bytes_to_big, lpg, gsize, g

        popad
        mov     eax, p
        mov     edx, g
        ret
    diffiehellman_set_params endp 

;-----------------------------------------------------------------------
; initializes Diffie-Hellman key exchange. Creates a random alice key
; and P=g^a mod p
; in : pointer to sdiffiehellman structure
; out: P from g^a mod p
    diffiehellman_init  proc    lpsdiffiehellman:dword
        local   _return:dword
        pushad
        mov     esi, lpsdiffiehellman

        invoke  diffiehellman_set_params, addr diffiehellman_generator, addr diffiehellman_prime, sizeof diffiehellman_generator, sizeof diffiehellman_prime
        mov     (sdiffiehellman ptr [esi]).prime, eax
        mov     (sdiffiehellman ptr [esi]).generator, edx 
        
        invoke  diffiehellman_generate_alice_random
        mov     (sdiffiehellman ptr [esi]).secret, eax

        invoke  diffiehellman_generate_alice_sharing, eax, (sdiffiehellman ptr [esi]).generator, (sdiffiehellman ptr [esi]).prime  
        mov     (sdiffiehellman ptr [esi]).sharing, eax
        mov     _return, eax
        
        popad
        mov     eax, _return
        ret
    diffiehellman_init  endp

;-----------------------------------------------------------------------
; free all Diffie-Hellman big nums    
    diffiehellman_destroy   proc    lpsdiffiehellman:dword

        invoke  big_destroy_array, lpsdiffiehellman, sizeof sdiffiehellman

        ret
    diffiehellman_destroy   endp
