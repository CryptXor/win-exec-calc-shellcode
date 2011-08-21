build_config = {
  "version": "0.1",
  "projects": {
    "w32-exec-calc-shellcode.bin": {
      "architecture": "x86",
      "files": {
        "w32-exec-calc-shellcode.bin": {
          "sources":  ["w32-exec-calc-shellcode.asm"],
        },
      },
    },
    "w32-exec-calc-shellcode-esp.bin": {
      "architecture": "x86",
      "files": {
        "w32-exec-calc-shellcode-esp.bin": {
          "sources":  ["w32-exec-calc-shellcode.asm"],
          "defines":  {"STACK_ALIGN": "TRUE"},
        },
      },
    },
    "w64-exec-calc-shellcode.bin": {
      "architecture": "x64",
      "files": {
        "w64-exec-calc-shellcode.bin": {
          "sources":  ["w64-exec-calc-shellcode.asm"],
        },
      },
    },
    "w64-exec-calc-shellcode-esp.bin": {
      "architecture": "x64",
      "files": {
        "w64-exec-calc-shellcode-esp.bin": {
          "sources":  ["w64-exec-calc-shellcode.asm"],
          "defines":  {"STACK_ALIGN": "TRUE"},
        },
      },
    },
    "win-exec-calc-shellcode.bin": {
      "architecture": "x86/x64",
      "files": {
        "win-exec-calc-shellcode.bin": {
          "sources":  ["win-exec-calc-shellcode.asm"],
        },
      },
    },
    "win-exec-calc-shellcode-esp.bin": {
      "architecture": "x86/x64",
      "files": {
        "win-exec-calc-shellcode-esp.bin": {
          "sources":  ["win-exec-calc-shellcode.asm"],
          "defines":  {"STACK_ALIGN": "TRUE"},
        },
      },
    },
  },
}
