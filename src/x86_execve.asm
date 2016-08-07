section .text
        global _start

_start:
	xor eax,eax		; clear registers
	xor ecx,ecx
	xor edx,edx

	push eax		; push string terminator
	push 0x68732f2f		; push 'hs//'
	push 0x6e69622f		; push 'nib/'

        mov al,11		; set to call execve
        mov ebx,esp		; set to point at our command
        int 80h			; execve /bin/sh
