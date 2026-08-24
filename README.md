<img width="1983" height="793" alt="ChatGPT Image Aug 24, 2026, 07_41_21 AM" src="https://github.com/user-attachments/assets/8e62e5c0-2f3e-4dfb-b934-4ffaffebc067" />


**ALIOTH** is a Windows-focused offensive security framework designed for authorized red-team operations, enterprise adversary simulation, malware analysis, security-control validation, and post-exploitation research.

[![Platform](https://img.shields.io/badge/Platform-Windows%20x64-0078D6)]()
[![Category](https://img.shields.io/badge/Category-Offensive%20Security-red)]()
[![Focus](https://img.shields.io/badge/Focus-Red%20Team%20%7C%20Adversary%20Simulation-orange)]()
[![Version](https://img.shields.io/badge/Version-3.0-black)]()

---

Use cases include:

* Authorized enterprise red-team engagements
* Adversary-emulation exercises
* Purple-team operations
* Active Directory security assessments
* Windows endpoint security assessments
* Post-exploitation research
* Malware analysis and reverse engineering
* EDR/XDR validation
* Detection-engineering validation
* Incident-response preparedness exercises
* Internal security research
* Authorized security-control testing

The framework is intended to model real-world adversary behavior in controlled engagements and can therefore interact with production-like enterprise environments when the engagement rules explicitly permit it.

---

# What is ALIOTH?

ALIOTH is a unified offensive security framework that combines 13 attack modes into a single standalone binary. No DLL dependencies, no runtime installers one .exe that covers the complete attack chain from initial access to data exfiltration and anti-forensics.

Every mode shares a common evasion engine indirect syscalls, stack spoofing, gadget rotation, ETW patching, HWBP clearing, polymorphic stubs. This is not a toolbox with 13 separate signatures. It is one binary, one evasion layer, protecting everything underneath.

At a high level:

```text
                         ALIOTH
                           │
          ┌────────────────┼────────────────┐
          │                │                │
       Execution       Credential       Enterprise
       & Memory         Research        Operations
          │                │                │
      ┌───┴───┐        ┌───┴───┐       ┌───┴────┐
      │ Umbra │        │Wraith │       │ Hermes │
      │Charon │        │Mortis │       │ Helios │
      │Revenant        │Shadow │       │  Nyx   │
      └───────┘        └───────┘       └────────┘
                           │
                 ┌─────────┴─────────┐
                 │                   │
             Persistence         Collection /
             & Evasion           Operations
                 │                   │
           ┌─────┴─────┐       ┌────┴──────┐
           │    Eos    │       │ Lachesis  │
           │  Acheron  │       │           │
           │ Tartarus  │       └───────────┘
           └───────────┘
```

---

# Where ALIOTH Can Be Used

ALIOTH is intended for authorized operations against environments such as:

### Active Directory Environments

```text
┌─────────────────────────────────────────┐
│             AD Environment              │
│                                         │
│  Domain Controller                      │
│       │                                 │
│       ├── Workstations                  │
│       ├── Servers                       │
│       ├── File Servers                  │
│       ├── SQL / Application Servers     │
│       ├── Admin Workstations            │
│       └── Security Infrastructure       │
│                                         │
└─────────────────────────────────────────┘
```

Typical red-team objectives may include evaluating:

* Credential exposure
* Privilege boundaries
* Kerberos security
* Lateral-movement controls
* Persistence detection
* Endpoint telemetry
* EDR/XDR visibility
* Network monitoring
* C2 detection
* Data-loss controls

### Windows Enterprise Environments

ALIOTH can be incorporated into authorized assessments involving:

* Windows endpoints
* Windows servers
* Domain-joined systems
* Enterprise application servers
* Security appliances
* Identity infrastructure
* Administrative workstations
* Internal network segments

### Red-Team Infrastructure
<img width="1536" height="1024" alt="ChatGPT Image Aug 23, 2026, 05_35_40 AM" src="https://github.com/user-attachments/assets/28412be4-f34a-443b-b8f2-cf78294afc83" />


---

# Core Capabilities

ALIOTH contains thirteen operational modes:

|  # | Mode     | Primary Area                                   |
| -: | -------- | ---------------------------------------------- |
| 01 | Umbra    | Execution & evasion research                   |
| 02 | Charon   | In-memory payload loading                      |
| 03 | Wraith   | Protected-process / credential-access research |
| 04 | Revenant | Process injection                              |
| 05 | Mortis   | Memory acquisition                             |
| 06 | Shadow   | Offline credential-store acquisition           |
| 07 | Hermes   | Kerberos operations                            |
| 08 | Eos      | Persistence                                    |
| 09 | Helios   | Lateral movement                               |
| 10 | Nyx      | C2 communications                              |
| 11 | Acheron  | Anti-forensics                                 |
| 12 | Lachesis | Data collection                                |
| 13 | Tartarus | Full-chain orchestration                       |

The complete mode inventory is defined in the supplied project guide.

Detailed mode internals are intentionally documented separately so the main README remains focused on installation, architecture, engagement use, and operator workflow.

---

# Installation

## Requirements

ALIOTH is a Windows/x64 project.

Recommended build environment:

```text
Windows 10 / Windows 11 x64
Visual Studio
Desktop development with C++
Windows SDK
MASM
Python 3.x
Git
```

The source project uses a Windows build script and Microsoft development tooling.

---

## Clone the Repository

```powershell
git clone <REPOSITORY_URL>
cd ALIOTH
```

Verify the development environment:

```powershell
cl
link
python --version
git --version
```

Open a **Visual Studio Developer Command Prompt** before building.

---

# Building ALIOTH

From the repository directory:

```powershell
cd C:\ALIOTH
.\build.bat
```

The supplied implementation supports configurable build-generation parameters through the build script.

For development environments, recommended repository structure is:

```text
ALIOTH/
├── build/
├── bin/
├── core/
├── modes/
└── tools/
```

Keep generated binaries separate from source code.

---

# Binary Layout

A normal build produces the primary ALIOTH executable and supporting development artifacts.

```text
ALIOTH/
│
├── ALIOTH.exe
├── build.bat
├── README.md
│
├── core/
│   ├── ALIOTH.h
│   ├── ALIOTH_config.h
│   ├── engine.h
│   ├── engine.c
│   ├── tls_context.h
│   ├── syscalls_base.asm
│   └── ...
│
└── modes/
    ├── umbra/
    ├── charon/
    ├── wraith/
    ├── revenant/
    ├── mortis/
    ├── shadow/
    ├── hermes/
    ├── eos/
    ├── helios/
    ├── nyx/
    ├── acheron/
    ├── lachesis/
    └── tartarus/
```

The supplied documentation describes this source organization and the shared `core/` plus 13 `modes/` architecture.

---

# Command-Line Interface

ALIOTH supports both interactive operation and direct mode selection.

### Interactive

```powershell
ALIOTH.exe
```

### Mode Selection

The general CLI structure is:

```powershell
ALIOTH.exe --mode <MODE>
```

or, where supported by a release build:

```powershell
ALIOTH.exe <MODE>
```

Examples:

```powershell
ALIOTH.exe 1
ALIOTH.exe 2
ALIOTH.exe 3
...
ALIOTH.exe 13
```

The project documentation defines these as modes `1` through `13`.

---

# Payload / `.bin` Workflow

Several ALIOTH components operate on binary payload artifacts.

The general workflow is:

```text
Payload
   │
   ▼
.bin artifact
   │
   ▼
Mode-specific preparation
   │
   ▼
ALIOTH build
   │
   ▼
Authorized target
```

For example, Charon uses a binary payload artifact and a dedicated preparation utility before the resulting artifact is incorporated into the build. The supplied documentation identifies `charon_builder.py` as the relevant preparation component.

A generic workflow looks like:

```powershell
python <mode-builder> --payload <payload.bin> --output <artifact>
```

Then rebuild:

```powershell
.\build.bat
```


# Active Directory Engagement

A common authorized assessment architecture:

```text
                RED TEAM
                   │
                   ▼
          Operator Infrastructure
                   │
             ALIOTH / C2
                   │
       ┌───────────┴────────────┐
       │                        │
       ▼                        ▼
 Domain Controller          Workstations
       │                        │
       ├── Identity             ├── Users
       ├── Kerberos             ├── Admins
       ├── LDAP                 ├── EDR
       └── Group Policy         └── Applications
```

# Engagement Profiles

ALIOTH can be incorporated into several types of authorized engagements.

## External Red Team

Focus:

```text
Internet-facing asset
       ↓
Initial access
       ↓
Endpoint compromise
       ↓
Internal access
       ↓
Identity expansion
       ↓
Objective
```

## Internal Red Team

Focus:

```text
Internal foothold
       ↓
AD enumeration
       ↓
Privilege boundaries
       ↓
Credential access
       ↓
Lateral movement
       ↓
High-value asset
```

## Purple Team

Focus on measurable detection:

```text
ALIOTH Technique
       ↓
Telemetry
       ↓
Detection
       ↓
SOC Alert
       ↓
Analyst Response
       ↓
Rule Improvement
```

## Malware Analysis

ALIOTH can also be used as a research subject when studying:

* Memory execution
* Windows internals
* Endpoint telemetry
* Process behavior
* Authentication behavior
* Persistence mechanisms
* Network behavior
* EDR detections

Use an isolated analysis environment and appropriate snapshots.

---

# Environment Preparation

A mature engagement environment should contain:

```text
Operator Host
       │
       ├── Source / Build Environment
       ├── Debugging Tools
       ├── Logging
       └── Engagement Notes
                │
                ▼
        Red-Team Infrastructure
                │
        ┌───────┴────────┐
        │                │
       C2              Proxy
        │
        ▼
    Target Network
```

For AD assessments, maintain accurate inventory of:

```text
Domain
Domain Controllers
Workstations
Servers
Administrative Accounts
Service Accounts
Security Products
Network Segments
Critical Applications
```

---

# Safety Controls During Engagement

Recommended operational controls:

### Scope Enforcement

Keep an explicit target allowlist.

```text
ALLOW:
  *.authorized-domain.local
  10.10.10.0/24

DENY:
  Everything else
```

# Configuration

Project configuration is centralized through the shared core configuration layer.

Relevant source components include:

```text
core/ALIOTH_config.h
core/tls_context.h
core/engine.h
```

The supplied project structure documents these components as part of the common execution engine.

Keep engagement-specific configuration outside public source repositories.

---

# Mode Invocation Convention

The framework follows a consistent convention:

```text
ALIOTH.exe --mode <MODE> [OPTIONS]
```

Common option categories include:

```text
--payload <file>
--target <name>
--output <file>
--pid <pid>
--server <host>
--port <port>
--sleep <seconds>
--jitter <seconds>
```

Mode-specific options are exposed by the corresponding module.

For security reasons, the public README intentionally avoids providing turnkey command lines for credential extraction, persistence, C2 deployment, unauthorized lateral movement, or security-control bypass.

---

# Detection Engineering Integration

ALIOTH is particularly useful when offensive activity is paired with defensive telemetry.

```text
              ALIOTH
                 │
                 ▼
          Technique Execution
                 │
        ┌────────┼────────┐
        ▼        ▼        ▼
      EDR      Sysmon    SIEM
        │        │        │
        └────────┼────────┘
                 ▼
             Detection
                 │
                 ▼
            SOC Response
                 │
                 ▼
         Detection Tuning
```

This makes the framework useful for validating whether security controls detect **behavior**, rather than merely matching known malware hashes.

---

# Source Tree

```text
ALIOTH/
│
├── ALIOTH.exe
├── build.bat
├── README.md
│
├── core/
│   ├── ALIOTH.h
│   ├── ALIOTH_config.h
│   ├── tls_context.h
│   ├── engine.h
│   ├── engine.c
│   ├── syscalls_base.asm
│   ├── generate_stubs.py
│   ├── etw_patch.c
│   ├── hwbp_check.c
│   ├── random_mask.c
│   ├── decoy_threads.c
│   └── utils.c
│
└── modes/
    ├── umbra/
    ├── charon/
    │   └── builder/
    ├── wraith/
    ├── revenant/
    ├── mortis/
    ├── shadow/
    ├── hermes/
    ├── eos/
    ├── helios/
    ├── nyx/
    ├── acheron/
    ├── lachesis/
    └── tartarus/
```

The project documentation identifies the shared core and all thirteen mode directories.

---

# Version

```text
Project     : ALIOTH
Version     : 3.0
Category    : Offensive Security Framework
Platform    : Windows x64
Author      : sn0x
Purpose     : Authorized Security Testing
```

The supplied guide identifies the project as ALIOTH v3.0 and labels it for authorized security testing.

---

# Disclaimer

ALIOTH is an offensive security research framework.

Use only where you have explicit authorization and an established scope of work.

The author is not responsible for damage, disruption, data loss, credential exposure, unauthorized access, or any other consequence resulting from misuse or deployment outside an authorized engagement.

ALIOTH exists to reproduce realistic adversarial behavior so security teams can understand where their controls succeed, where they fail, and what needs to be improved.
