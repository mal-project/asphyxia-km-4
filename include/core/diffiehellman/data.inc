; Diffie-Hellman key exchange
;-----------------------------------------------------------------------
sdiffiehellman  struct
    prime       hBIG  ?
    generator   hBIG  ?
    secret      hBIG  ?
    sharing     hBIG  ?
sdiffiehellman  ends

;-----------------------------------------------------------------------
diffiehellman_init      proto   :dword
diffiehellman_destroy   proto   :dword
diffiehellman_calculate_s   proto   :dword, :dword, :dword
diffiehellman_set_params    proto   :dword, :dword, :dword, :dword
diffiehellman_generate_alice_random     proto
diffiehellman_generate_alice_sharing    proto   :dword, :dword, :dword

;-----------------------------------------------------------------------
.const
    ; "FCB827459E55CE9B" prime (18210348273235250843)
    diffiehellman_prime         db 0FCh, 0B8h, 027h, 045h, 09Eh, 055h, 0CEh, 09Bh
    ; "D875D8C7F91" generator (14875041234833)
    diffiehellman_generator     db 00Dh, 087h, 05Dh, 08Ch, 07Fh, 091h

;-----------------------------------------------------------------------
.data?
    diffiehellman   sdiffiehellman <?>

;-----------------------------------------------------------------------
