; Copyright (c) 2009-2013, Berend-Jan "SkyLined" Wever <berendjanwever@gmail.com>
; and Peter Ferrie <peter.ferrie@gmail.com>
; Project homepage: http://code.google.com/p/win-exec-calc-shellcode/
; All rights reserved. See COPYRIGHT.txt for details.

; null-free x86/x64 branching code for calc.exe executing shellcode.
; Works in any x86 or x64 application for Windows 5.0-6.3 all service packs.
BITS 32

global shellcode
shellcode:

%ifdef STACK_ALIGN
    AND     SP, 0xFFF8
%endif
    ; x86                         ; x64
    XOR   ECX, ECX                ; --->  XOR   ECX, ECX
    DEC   ECX                     ; -,->  XOR   RDX, R10
    XOR   EDX, EDX                ; /
    JECXZ w64_exec_calc_shellcode ; 

; Because the stack has been aligned (if requested), this does not need to get
; done in the x86/x64 shellcodes.
%undef STACK_ALIGN
; Because ECX is set to 0 or -1, a few more size optimizations are possible in
; the x86/x64 shellcodes.
%define PLATFORM_INDEPENDENT

; Since ECX gets decremented on x86, the code did not branch but falls through
; into the x86 shellcode.
w32_exec_calc_shellcode:
%include "w32-exec-calc-shellcode.asm"

; Since ECX does NOT get decremented on x64, the code did branch to the x64
; shellcode.
w64_exec_calc_shellcode:
%include "w64-exec-calc-shellcode.asm"
