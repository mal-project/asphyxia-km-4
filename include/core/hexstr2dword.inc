;컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴�
; mov	ecx, iNum
; mov   edi,offset buffer
; call  _hexstr2dword
;
; konvertuje stringa podanego w buforze na DWORDa do rejestru EAX
;
; na wejsciu:
; buffer - offset bufora gdzie jest zapisany
;          hexstring
; ecx - ilosc znakow do przekonwertowania (1-8) :P
;
; na wyjsciu:
; eax    - przekonwertowany hexstring
;
; modyfikowane rejestry:
; eax,ecx,edx
;
; shield/UnderPl
; modyfikacje by ged_/tkm!
;컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴asmpak�
hexstr2dword proc uses esi edx ebx

	xor     eax,eax			; zerowanie eax

	push    8			; liczba powtorzen petli
	pop	    ecx			; do rejestru ecx
_1:
	mov     dl,byte ptr [esi]	; znak do dl
	cmp	    dl,0			; czy koniec
	je	    _3
	sub	    dl,30h			; zamien na hex
	cmp	    dl,9
	jna 	_2
	sub	    dl,7
	cmp	    dl,0Fh
	jna	    _2
	sub     dl,20h
_2:
	add	    al,dl			; zapisz do eax
	rol	    eax,4
	inc	    esi
	dec	    ecx
	jne	    _1

_3:
	ror	    eax,4
	bswap   eax

	ret

hexstr2dword endp