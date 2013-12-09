build_config = {
  "version": "0.1",
  "debug": True,
  "projects": {
    "build\\bin\\w32-exec-calc-shellcode.bin": {
      "architecture": "x86",
      "files": {
        "build\\bin\\w32-exec-calc-shellcode.bin": {
          "sources": ["w32-exec-calc-shellcode.asm"],
        },
      },
    },
    "build\\bin\\w32-exec-calc-shellcode-esp.bin": {
      "architecture": "x86",
      "files": {
        "build\\bin\\w32-exec-calc-shellcode-esp.bin": {
          "sources": ["w32-exec-calc-shellcode.asm"],
          "defines": {"STACK_ALIGN": "TRUE"},
        },
      },
    },
    "build\\bin\\w32-exec-calc-shellcode-func.bin": {
      "architecture": "x86",
      "files": {
        "build\\bin\\w32-exec-calc-shellcode-func.bin": {
          "sources": ["w32-exec-calc-shellcode.asm"],
          "defines": {"FUNC": "TRUE"},
        },
      },
    },
    "build\\bin\\w32-exec-calc-shellcode-clean-func.bin": {
      "architecture": "x86",
      "files": {
        "build\\bin\\w32-exec-calc-shellcode-clean-func.bin": {
          "sources": ["w32-exec-calc-shellcode.asm"],
          "defines": {"CLEAN": "TRUE", "FUNC": "TRUE"},
        },
      },
    },
    "build\\bin\\w64-exec-calc-shellcode.bin": {
      "architecture": "x64",
      "files": {
        "build\\bin\\w64-exec-calc-shellcode.bin": {
          "sources": ["w64-exec-calc-shellcode.asm"],
        },
      },
    },
    "build\\bin\\w64-exec-calc-shellcode-esp.bin": {
      "architecture": "x64",
      "files": {
        "build\\bin\\w64-exec-calc-shellcode-esp.bin": {
          "sources": ["w64-exec-calc-shellcode.asm"],
          "defines": {"STACK_ALIGN": "TRUE"},
        },
      },
    },
    "build\\bin\\w64-exec-calc-shellcode-func.bin": {
      "architecture": "x64",
      "files": {
        "build\\bin\\w64-exec-calc-shellcode-func.bin": {
          "sources": ["w64-exec-calc-shellcode.asm"],
          "defines": {"FUNC": "TRUE"},
        },
      },
    },
    "build\\bin\\w64-exec-calc-shellcode-clean-func.bin": {
      "architecture": "x64",
      "files": {
        "build\\bin\\w64-exec-calc-shellcode-clean-func.bin": {
          "sources": ["w64-exec-calc-shellcode.asm"],
          "defines": {"CLEAN": "TRUE", "FUNC": "TRUE"},
        },
      },
    },
    "build\\bin\\win-exec-calc-shellcode.bin": {
      "architecture": "x86/x64",
      "files": {
        "build\\bin\\win-exec-calc-shellcode.bin": {
          "sources": ["win-exec-calc-shellcode.asm"],
        },
      },
    },
    "build\\bin\\win-exec-calc-shellcode-esp.bin": {
      "architecture": "x86/x64",
      "files": {
        "build\\bin\\win-exec-calc-shellcode-esp.bin": {
          "sources": ["win-exec-calc-shellcode.asm"],
          "defines": {"STACK_ALIGN": "TRUE"},
        },
      },
    },
    "build\\dll\\w32-exec-calc-shellcode.dll": {
      "architecture": "x86",
      "dependencies": ["build\\bin\\w32-exec-calc-shellcode.bin"],
      "files": {
        "build\\dll\\w32-exec-calc-shellcode.dll": {
          "sources": ["build\\w32-exec-calc-shellcode.obj", "build\\w32-dll-run-shellcode.obj"],
        },
        "build\\w32-exec-calc-shellcode.obj": {
          "sources": ["w32-exec-calc-shellcode.asm"],
          "defines": {"FUNC": "TRUE"},
        },
        "build\\w32-dll-run-shellcode.obj": {
          "sources": ["win-dll-run-shellcode.c"],
        }
      }
    },
    "build\\dll\\w64-exec-calc-shellcode.dll": {
      "architecture": "x64",
      "dependencies": ["build\\bin\\w64-exec-calc-shellcode.bin"],
      "files": {
        "build\\dll\\w64-exec-calc-shellcode.dll": {
          "sources": ["build\\w64-exec-calc-shellcode.obj", "build\\w64-dll-run-shellcode.obj"],
        },
        "build\\w64-exec-calc-shellcode.obj": {
          "sources": ["w64-exec-calc-shellcode.asm"],
          "defines": {"FUNC": "TRUE"},
        },
        "build\\w64-dll-run-shellcode.obj": {
          "sources": ["win-dll-run-shellcode.c"],
        }
      }
    },
    "build\\exe\\w32-exec-calc-shellcode.exe": {
      "architecture": "x86",
      "dependencies": ["build\\bin\\w32-exec-calc-shellcode.bin"],
      "files": {
        "build\\exe\\w32-exec-calc-shellcode.exe": {
          "sources": ["build\\w32-exec-calc-shellcode.obj", "build\\w32-exe-run-shellcode.obj"],
        },
        "build\\w32-exec-calc-shellcode.obj": {
          "sources": ["w32-exec-calc-shellcode.asm"],
          "defines": {"FUNC": "TRUE"},
        },
        "build\\w32-exe-run-shellcode.obj": {
          "sources": ["win-exe-run-shellcode.c"],
        }
      }
    },
    "build\\exe\\w64-exec-calc-shellcode.exe": {
      "architecture": "x64",
      "dependencies": ["build\\bin\\w64-exec-calc-shellcode.bin"],
      "files": {
        "build\\exe\\w64-exec-calc-shellcode.exe": {
          "sources": ["build\\w64-exec-calc-shellcode.obj", "build\\w64-exe-run-shellcode.obj"],
        },
        "build\\w64-exec-calc-shellcode.obj": {
          "sources": ["w64-exec-calc-shellcode.asm"],
          "defines": {"FUNC": "TRUE"},
        },
        "build\\w64-exe-run-shellcode.obj": {
          "sources": ["win-exe-run-shellcode.c"],
        }
      }
    },
  },
}
