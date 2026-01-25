# Shellcode Crafting Guide

## Overview
Manual and automated techniques for crafting custom shellcode.

## Assembly Fundamentals

### x86 Shellcode
- Register conventions
- System call interface
- Position independence
- Null byte avoidance

### x64 Shellcode
- Calling conventions
- Syscall numbers
- Red zone awareness
- Register usage

### ARM Shellcode
- Thumb mode tricks
- Branch instructions
- Immediate encoding
- Cache coherency

## Crafting Techniques

### Socket Programming
- Reverse connect shells
- Bind shell variants
- UDP shells
- ICMP tunneling

### Process Control
- Fork/exec patterns
- Setuid operations
- Signal handling
- PTY spawning

### Windows Shellcode
- PEB walking
- API hashing
- DLL loading
- Thread injection

## Optimization

### Size Reduction
- Instruction selection
- Register reuse
- Self-modifying code
- Compression stubs

### Encoding
- Alphanumeric shellcode
- Unicode safe encoding
- Polymorphic engines
- Self-decrypting stubs

## Testing Framework
- Execution harness
- Debugging tips
- Cross-platform testing

## Legal Notice
For security research only.
