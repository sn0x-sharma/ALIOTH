#pragma once

#include <windows.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================
// XOR CRYPTO UTILITIES
// ============================================================

// XOR encrypt/decrypt with repeating key (20-char key for HollowReaper compatibility)
void ALIOTHXorEncrypt(const unsigned char* input, size_t input_len, const unsigned char* key, size_t key_len, unsigned char* output);

// XOR decrypt (same as encrypt for XOR)
#define ALIOTHXorDecrypt ALIOTHXorEncrypt

// XOR with 20-char string key (HollowReaper compatibility)
void ALIOTHXorEncrypt20CharKey(const unsigned char* input, size_t input_len, const char* key20, unsigned char* output);

// XOR with arbitrary key
void ALIOTHXorWithKey(const unsigned char* input, size_t input_len, const unsigned char* key, size_t key_len, unsigned char* output);

// RC4 encryption (Charon UUIDEncrypter compatibility)
void ALIOTHRc4Encrypt(const unsigned char* key, size_t key_len, const unsigned char* data, size_t data_len, unsigned char* output);

// RC4 decryption (same as encrypt for RC4)
#define ALIOTHRc4Decrypt ALIOTHRc4Encrypt

// RC4 with KeyGuard (Charon KeyGuard logic)
void ALIOTHRc4KeyGuard(const unsigned char* real_key, unsigned char* protected_key, unsigned char* hint_byte);

// ============================================================
// SHELLCODE ENCODING UTILITIES
// ============================================================

// Encode shellcode as raw UUIDs (Charon UUIDEncrypter compatibility)
void ALIOTHEncodeShellcodeToUuids(const unsigned char* shellcode, size_t shellcode_len, char* uuid_output, size_t uuid_output_size);

// Encode shellcode as C array (0xXX, 0xXX, ...)
void ALIOTHEncodeShellcodeToCArray(const unsigned char* shellcode, size_t shellcode_len, char* output, size_t output_size);

// ============================================================
// API NAME ENCRYPTION (Doppelganger APINameEncrypter)
// ============================================================

// Encrypt API name with XOR key
void ALIOTHEncryptApiName(const char* api_name, const char* key, unsigned char* output, size_t* output_len);

// Pre-encrypted API names (from Doppelganger)
extern const unsigned char ENCRYPTED_API_NAMES[][64];
extern const size_t ENCRYPTED_API_LENS[];
extern const char* API_NAMES[];
extern const size_t NUM_API_NAMES;

// ============================================================
// XOR DUMP DECRYPTION (Doppelganger decrypt_xor_dump.py)
// ============================================================

// Decrypt XOR-encrypted dump file
BOOL ALIOTHDecryptXorDump(const char* encrypted_path, const char* output_path, const unsigned char* key, size_t key_len);

// Default XOR key for Doppelganger dumps
extern const unsigned char DEFAULT_XOR_KEY[20];

// ============================================================
// KERBEROS TICKET EXTRACTION (Doppelganger raw_TGT_extractor_win11.py)
// ============================================================

// Extract Kerberos tickets from memory dump
int ALIOTHExtractKerberosTickets(const char* dump_file, const char* output_dir);

// ============================================================
// SHELLCODE XOR UTILITY (HollowReaper xor20charkey.py)
// ============================================================

// XOR shellcode with 20-char key, output as C array
void ALIOTHXorShellcode20Char(const unsigned char* shellcode, size_t shellcode_len, const char* key20, char* output, size_t output_size);

// ============================================================
// UUID ENCODING (Charon UUIDEncrypter)
// ============================================================

// Encode binary data as UUID strings
void ALIOTHBytesToRawUuids(const unsigned char* data, size_t size, char* uuid_str, size_t uuid_str_size);

// RC4 with KeyGuard (Charon)
void ALIOTHRc4KeyGuardEncrypt(const unsigned char* real_key, unsigned char* protected_key, unsigned char* hint_byte, unsigned char b);

// ============================================================
// POLYMORPHIC STUB GENERATOR (Obolos generate_stubs.py)
// ============================================================

// Generate polymorphic syscall stubs
void ALIOTHGeneratePolymorphicStubs(int stub_count, const char* base_file, const char* output_file);

// Padding types for polymorphic stubs
typedef enum {
    ALIOTH_PADDING_NOP = 0,
    ALIOTH_PADDING_XCHG_R8 = 1,
    ALIOTH_PADDING_XCHG_AX = 2,
    ALIOTH_PADDING_MIXED = 3
} ALIOTH_PADDING_TYPE;

void ALIOTHGenerateStub(int index, ALIOTH_PADDING_TYPE padding_type, char* output, size_t output_size);

#ifdef __cplusplus
}
#endif
