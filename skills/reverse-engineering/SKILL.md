---
name: reverse-engineering
description: Reverse engineering methodology for closed-source binaries and firmware. Covers static analysis (radare2/Ghidra/IDA), dynamic analysis (GDB/Lighthouse), decompilation, protocol reverse engineering, obfuscation deobfuscation, binary diffing, and firmware extraction/analysis. Use when you need to understand what a binary does without source code, find backdoors, extract algorithms, or patch binaries.
---

# Reverse Engineering Methodology

## Phase 0: Binary Reconnaissance

```bash
file target.bin
readelf -h target
objdump -f target
strings target | head -50
strings -e l target | head -50
```

## Phase 1: Static Analysis

### radare2 Workflow

```bash
r2 target
> aaaa                # analyze everything
> afl                 # list all functions
> afl~calls           # functions making external calls
> afl~syscall         # functions making syscalls
> s main              # seek to main
> pdc                 # pseudo-code decompile
> VV                  # control flow graph
> axt                 # cross-references to current
> iz                  # strings in data section
> is                  # symbols/imports
```

### Ghidra Headless

```bash
/path/to/ghidra/support/analyzeHeadless /tmp/ghidra_proj \
  -import target \
  -postScript /path/to/ExportDecompileScript.java
```

## Phase 2: Algorithm Extraction

```bash
# Look for crypto constants (AES S-box first 16 bytes: 63 7C 77 7B F2 6B 6F C5 ...)
objdump -s -j .rodata target | grep -E "637c|776b"

# Obfuscation detection
objdump -d target | grep -E "xor.*0x[0-9a-fA-F]{2,}"
```

## Phase 3: Binary Diffing

```bash
# Compare two versions
radiff2 -a x86 -d target_v1 target_v2  # delta diff
radiff2 -a x86 -s target_v1 target_v2  # symbolic diff
```

## Phase 4: Firmware Analysis

```bash
# File extraction
binwalk -Me firmware.bin
# If filesystem found:
unsquashfs rootfs.squashfs  # SquashFS
jefferson rootfs.jffs2      # JFFS2

# Default credential check
grep -rn "password\|admin\|root\|telnet\|ssh\|backdoor" extracted/
```

## Phase 5: Common Patterns

| Pattern | Indicator |
|---------|-----------|
| XOR obfuscation | `xor reg, 0xNN` with constant key |
| API hashing | Functions called via hash table lookup |
| Import obfuscation | Dynamic GetProcAddress/LoadLibrary |
| Anti-debug | IsDebuggerPresent, NtQueryInformationProcess, ptrace |
| String encoding | XOR/Base64/Rot strings at runtime |
| Opaque predicates | Always-true jump conditions (anti-analysis) |
