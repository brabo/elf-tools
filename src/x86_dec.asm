section .text
        global _start

_start:
	jmp short three

one:
	pop esi
	xor ecx, ecx
	mov cl, 23   			; we load the length of the shellcode in memory (counter)

two:
	sub byte [esi + ecx -1 ], 1	; we substract 1 from the byte (decoding)
	sub cl,2			; we substract 1 from the counter
	jnz two				; test if cl = 0 (done)
	jmp short four			; done, let's execute shellcode

three:
	call one

four:
	nop
