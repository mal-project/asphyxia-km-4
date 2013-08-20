;-----------------------------------------------------------------------
Comment % Blowfish - My very little simple implemantation ;)

(August, 13th 2000) - v1.0 - Written by Lucifer48 [PC/ID]

(modified by Asphyxia's motherfucker - 6/16/2009)

3 functions:

* blowfish_init
  (exemple: invoke blowfish_init, addr my_key, sizeof my_key)

* blowfish_encrypt
  (exemple: invoke blowfish_encrypt, addr lpdata, sizeof lpdata, addr lpbuffer)

* blowfish_decrypt
  (exemple: invoke blowfish_decrypt, addr lpdata, sizeof lpdata, addr lpbuffer)

- data length should be multiple of block size (64 bits)
- lpbuffer can be null then buffer is lpdata (overwritten original data with encrypted one)

%
;-----------------------------------------------------------------------
blowfish_init       proto   :dword, :dword
blowfish_encrypt    proto   :dword, :dword, :dword
blowfish_decrypt    proto   :dword, :dword, :dword

;-----------------------------------------------------------------------