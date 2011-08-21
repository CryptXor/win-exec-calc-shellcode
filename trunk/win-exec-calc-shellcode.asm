; Copyright (c) 2009-2011, Berend-Jan "SkyLined" Wever <berendjanwever@gmail.com>
; Project homepage: http://code.google.com/p/win-exec-calc-shellcode/
; All rights reserved. See COPYRIGHT.txt for details.
BITS 32
; null-free x86/x64 branching code for calc.exe executing shellcode.
; (See http://skypher.com/wiki/index.php/Hacking/Shellcode).
; This code is based on http://www.ragestorm.net/blogs/?p=376

    XOR   EAX, EAX
    INC   EAX
    JZ    w64_exec_calc_shellcode
; In x64 opcodes, this translates to:
;   XOR   EAX, EAX
;   [REX prefix with all flags 0]
;   JZ    w64_exec_calc_shellcode
; This code should be followed by the x86 and the x64 shellcode, in that order.
; Since EAX gets incremented on x86, the code does not branch and the x86 code
; is executed. Since EAX does NOT get incremented on x64, the code DOES branch
; to the x64 code.
w32_exec_calc_shellcode:
%include "w32-exec-calc-shellcode.asm"
w64_exec_calc_shellcode:
%include "w64-exec-calc-shellcode.asm"
