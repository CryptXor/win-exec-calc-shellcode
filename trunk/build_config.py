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
    "w32-exec-calc-shellcode.dll": {
      "architecture": "x86",
      "dependencies": ["w32-exec-calc-shellcode.bin"],
      "files": {
        "w32-exec-calc-shellcode.dll": {
          "sources": ["w32-exec-calc-shellcode.obj", "w32-dll-run-shellcode.obj"]
        },
        "w32-exec-calc-shellcode.obj": {
          "sources": ["w32-exec-calc-shellcode.asm"]
        },
        "w32-dll-run-shellcode.obj": {
          "sources": ["win-dll-run-shellcode.c"]
        }
      }
    },
    "w32-exec-calc-shellcode.exe": {
      "architecture": "x86",
      "dependencies": ["w32-exec-calc-shellcode.bin"],
      "files": {
        "w32-exec-calc-shellcode.exe": {
          "sources": ["w32-exec-calc-shellcode.obj", "w32-dll-run-shellcode.obj"]
        },
        "w32-exec-calc-shellcode.obj": {
          "sources": ["w32-exec-calc-shellcode.asm"]
        },
        "w32-dll-run-shellcode.obj": {
          "sources": ["win-exe-run-shellcode.c"]
        }
      }
    },
    "w64-exec-calc-shellcode.dll": {
      "architecture": "x64",
      "dependencies": ["w64-exec-calc-shellcode.bin"],
      "files": {
        "w64-exec-calc-shellcode.dll": {
          "sources": ["w64-exec-calc-shellcode.obj", "w64-dll-run-shellcode.obj"]
        },
        "w64-exec-calc-shellcode.obj": {
          "sources": ["w64-exec-calc-shellcode.asm"]
        },
        "w64-dll-run-shellcode.obj": {
          "sources": ["win-dll-run-shellcode.c"]
        }
      }
    },
    "w64-exec-calc-shellcode.exe": {
      "architecture": "x64",
      "dependencies": ["w64-exec-calc-shellcode.bin"],
      "files": {
        "w64-exec-calc-shellcode.exe": {
          "sources": ["w64-exec-calc-shellcode.obj", "w64-dll-run-shellcode.obj"]
        },
        "w64-exec-calc-shellcode.obj": {
          "sources": ["w64-exec-calc-shellcode.asm"]
        },
        "w64-dll-run-shellcode.obj": {
          "sources": ["win-exe-run-shellcode.c"]
        }
      }
    },
  },
}
