; Copyright (c) 2009-2011, Berend-Jan "SkyLined" Wever <berendjanwever@gmail.com>
; Project homepage: http://code.google.com/p/win-exec-calc-shellcode/
; All rights reserved. See COPYRIGHT.txt for details.
BITS 32
; null-free x86/x64 branching code for calc.exe executing shellcode.
; (See http://skypher.com/wiki/index.php/Hacking/Shellcode).
; This code is based on http://www.ragestorm.net/blogs/?p=376

%ifdef STACK_ALIGN
    AND     SP, 0xFFFC
%endif

    ;no undocumented use of REX with potentially unpleasant future side-effects
    XOR   ECX, ECX
    XOR   RDX, R10
    JECXZ w64_exec_calc_shellcode
; In x64 opcodes, this translates to:
;   XOR   ECX, ECX (and now RCX is zero)
;   [REX prefix instruction in 64-bit, "DEC ECX" and "XOR EDX, EDX" in 32-bit]
;   JECXZ w64_exec_calc_shellcode

; Because the stack has been aligned (if requested), this does not need to get
; done in the x86/x64 shellcodes.
%undef STACK_ALIGN
; Because EAX is set to 1 or 0, a few more size optimizations are possible in
; the x86/x64 shellcodes.
%define PLATFORM_INDEPENDENT  

; Since EAX gets incremented on x86, the code did not branch but falls through
; into the x86 shellcode.
w32_exec_calc_shellcode:
%include "w32-exec-calc-shellcode.asm"

; Since EAX does NOT get incremented on x64, the code did branch to the x64
; shellcode.
w64_exec_calc_shellcode:
%include "w64-exec-calc-shellcode.asm"
