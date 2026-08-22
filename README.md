# ALIOTH — Unified Offensive Security Framework

ALIOTH is a single, mode-based executable combining 13 offensive security capabilities into one standalone tool. It uses a common evasion engine for all syscalls and provides state-of-the-art bypass techniques for modern Windows 10/11 environments including 24H2.

## Modes

| Mode | Name | Description | Original Tool |
|------|------|-------------|---------------|
| 1 | **Umbra** | Evasion engine demo — indirect syscalls, stack spoofing, Halo's Gate | Obolos |
| 2 | **Charon** | Shellcode loader — module stomping, AES-NI/RC4 decryption, callback execution | Charon |
| 3 | **Wraith** | LSASS dumper with PPL bypass — BYOVD chain, process cloning, ChaCha20-Poly1305 | Doppelganger |
| 4 | **Revenant** | Process hollowing — transacted hollowing, thread hijacking, TLS callback | HollowReaper |
| 5 | **Mortis** | LSASS MiniDump — manual minidump, selective regions, crash handler | SoulDumper |
| 6 | **Shadow** | VSS SAM dumper — COM interface, raw disk read, hive parsing | NecroMirror |
| 7 | **Hermes** | Kerberos TGT injection — LSA interface, silver/golden tickets, cross-domain | TGTConjuring |
| 8 | **Eos** | Persistence engine — 10 techniques (Registry, Task Scheduler, WMI, COM, IFEO, LSA, Bootkit, AppX) | New |
| 9 | **Helios** | Lateral movement — 10 techniques (PTH, WMI, PSExec, DCOM, Pipe, RDP, WinRM, SSH, PTK, GPO) | New |
| 10 | **Nyx** | C2 communication — 10 channels (HTTPS, DNS, ICMP, SMB, WS, DoH, Telegram, GitHub, WCF, OneDrive) | New |
| 11 | **Acheron** | Anti-forensics — 10 techniques (EventLog, Prefetch, USN, Timestomp, Shredder, AMSI, ETW, KernelCB, PE Infector, Shim) | New |
| 12 | **Lachesis** | Data theft — 10 modules (Chrome, Firefox, Cookies, WiFi, Files, Screen, Webcam, Keylogger, Clipboard) | New |
| 13 | **Tartarus** | FULL AUTO APT — 10 phases (Elevate→UAC→PPL→Dump→Persist→Wipe→C2→Lateral→Steal→Decoy) | New |

## Quick Start

```cmd
REM Build with 1024 polymorphic stubs
build.bat 1024

REM Or 2048 for more entropy
build.bat 2048

REM Run interactive
ALIOTH.exe

REM Or direct mode
ALIOTH.exe --mode 3 --memory-only --encrypt
```

## Features

- **Common Evasion Engine**: All modes use ALIOTH core for indirect syscalls, stack spoofing, gadget rotation, SSN obfuscation
- **Polymorphic Stubs**: 1024/2048 unique stubs with 4 padding variants per build
- **TLS Per-Thread Context**: Zero global state, fully thread-safe
- **ETW Patching**: Kills Event Tracing via direct syscall
- **HWBP Detection**: Clears DR0-DR3 debug registers
- **Decoy Threads**: 4 background threads with realistic behaviors
- **XOR-Obfuscated Strings**: All string literals as stack character arrays
- **No CRT Dependencies**: Pure C, MSVC x64 /O1 /GS- /GF- /Gy compilable

## Requirements

- Windows 10/11 x64 (tested on 24H2)
- Visual Studio 2022 with C++ Desktop Development
- Developer Command Prompt for VS (for ml64/cl)
- Python 3.x (for stub generation)

## Usage Examples

### Umbra (Engine Test)
```cmd
ALIOTH.exe --mode 1
```

### Charon (Load Shellcode)
```cmd
REM Generate artifact
python modes\charon\builder\charon_builder.py --payload beacon.bin --target Chakra.dll

REM Execute
ALIOTH.exe --mode 2 --shellcode beacon.bin --target Chakra.dll
```

### Wraith (Dump LSASS)
```cmd
ALIOTH.exe --mode 3 --memory-only --encrypt --split
```

### Revenant (Hollow Process)
```cmd
ALIOTH.exe --mode 4 --target RuntimeBroker --payload shellcode.bin --technique 1
```

### Mortis (MiniDump)
```cmd
ALIOTH.exe --mode 5 --selective --memory-only
```

### Shadow (VSS SAM)
```cmd
ALIOTH.exe --mode 6 --delete-after-read --direct-read
```

### Hermes (TGT Injection)
```cmd
ALIOTH.exe --mode 7 --user administrator --domain corp.local --golden
```

### Tartarus (Full Auto APT)
```cmd
ALIOTH.exe --mode 13
```

## Architecture

```
ALIOTH.exe
├── Core Engine (shared by all modes)
│   ├── Indirect Syscalls (Halo's Gate)
│   ├── Stack Spoofing (SilentMoonwalk)
│   ├── Gadget Rotation (8 gadgets)
│   ├── SSN Obfuscation (XOR at rest)
│   ├── Mask Chaining (multi-frame)
│   ├── TLS Context (per-thread)
│   ├── ETW Patching
│   ├── HWBP Detection
│   ├── Random Masks (256+)
│   └── Decoy Threads (4 threads)
│
├── Mode 1: Umbra — Engine Demo
├── Mode 2: Charon — Shellcode Loader
├── Mode 3: Wraith — LSASS Dumper
├── Mode 4: Revenant — Process Hollowing
├── Mode 5: Mortis — LSASS MiniDump
├── Mode 6: Shadow — VSS SAM Dumper
├── Mode 7: Hermes — Kerberos TGT
├── Mode 8: Eos — Persistence Engine
├── Mode 9: Helios — Lateral Movement
├── Mode 10: Nyx — C2 Communication
├── Mode 11: Acheron — Anti-Forensics
├── Mode 12: Lachesis — Data Theft
└── Mode 13: Tartarus — FULL AUTO APT
```

## Disclaimer

This tool is for authorized security testing and educational purposes only. Unauthorized use against systems you do not own or have explicit permission to test is illegal. The author accepts no liability for misuse.

---

**Author**: sn0x
