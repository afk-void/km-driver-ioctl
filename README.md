# Windows Kernel-Mode (IOCTL) Driver

This repository contains a Windows kernel-mode (IOCTL) driver that implements
low-level process interaction, cross-process memory manipulation, signature
scanning, and kernel-level input injection through a custom IOCTL interface.

This driver is intentionally detectable and demonstrates techniques that are
actively monitored, flagged, and patched by modern anti-cheat and EDR systems.
The purpose of this project is technical demonstration,
not stealth or evasion.

---

## Technical Overview

The driver exposes a user-mode controlled IOCTL interface that enables direct
interaction with kernel subsystems and target processes. All operations are
performed in kernel space and bypass standard user-mode restrictions.

---

## Implemented Capabilities

### IOCTL Communication
- Custom IOCTL definitions and request structures
- Centralized IRP dispatch handling
- Kernel to user-mode command routing

### Process Context Control
- Kernel-level process attachment and detachment
- Context switching using NT kernel primitives
- Safe execution within remote process contexts

### Virtual Memory Management
- Allocate virtual memory in remote processes
- Free and swap virtual memory regions
- Modify page protection flags
- Query virtual memory layout and attributes

### Memory Read / Write
- Arbitrary kernel-level read and write of process memory
- Cross-process memory access without user-mode APIs

### Module Inspection
- Resolve and cache module base addresses
- Inspect loaded modules inside target processes

### Signature / Pattern Scanning
- Byte-pattern scanning within process memory
- Locate dynamic or non-exported structures

### Kernel-Level Input Injection
- Mouse input injection from kernel space
- Interaction with input driver stacks
- Bypasses standard user-mode input APIs

### Custom Runtime and Imports
- Custom CRT implementation
- Manual kernel import resolution
- Encrypted or obfuscated static data
- Internal NT kernel structure definitions

---

## Build Requirements

- Windows 10 or Windows 11 (x64)
- Visual Studio with Windows Driver Kit (WDK)
- Driver development workload enabled

---

## Build Instructions

1. Open the solution in Visual Studio
2. Select x64 and Debug or Release
3. Build the project
4. Output will be a compiled .sys kernel driver

---

## Driver Loading (Development)

Enable test signing:

bcdedit /set testsigning on

Reboot the system and load the driver using a driver loader or sc.exe.

OR

[KDMapper](https://github.com/TheCruZ/kdmapper)

---

## Detection Context

This driver uses techniques commonly employed in kernel-level tooling and is
expected to be detected by modern anti-cheat systems. The implementation is
explicit and deliberate so detection logic and patching strategies can be
studied and improved.

---

## Intended Audience

- Kernel-mode developers
- Reverse engineers
- Anti-cheat engineers
- EDR engineers
- Security researchers

---

## Disclaimer

Running kernel-mode code can crash or destabilize systems.
Use only in controlled environments or virtual machines.
