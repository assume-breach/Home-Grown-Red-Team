Shareable is a proof of concept executable that allows an attacker to run a hosted shellcode file from a shared network folder. 

Execution:

Here we have a raw Havoc shellcode file renamed to reflect a TXT file located on a shared network folder accessible to the domain controller.

![Screenshot 2023-11-15 at 10 11 52 AM](https://github.com/assume-breach/Home-Grown-Red-Team/assets/76174163/7610bd6a-36bd-4ada-8731-afffbad4bd20)

On our POC, we enter the folder/file location and hostname.

![Screenshot 2023-11-15 at 11 40 07 AM](https://github.com/assume-breach/Home-Grown-Red-Team/assets/76174163/21e8deb3-08d4-42f0-b547-aaeeb3a93aa6)

We then compile x86_64-w64-mingw32-g++ -o sharable.exe sharable.cpp -lws2_32 -lntdll

We upload the executable to the domain controller and execute.

![Screenshot 2023-11-15 at 11 45 13 AM](https://github.com/assume-breach/Home-Grown-Red-Team/assets/76174163/6ccbe5ff-44da-462f-9718-da6bc3c0d26f)

And we get a Havoc beacon back. 

![Screenshot 2023-11-15 at 12 20 34 PM](https://github.com/assume-breach/Home-Grown-Red-Team/assets/76174163/e9bb32ce-c62f-4061-9e71-f07e41d788b7)

Considerations:

This POC uses userland WinAPIs. There have been zero OPSEC considerations in this POC. If you consider using this, modify it to use syscalls. You will also notice that the memory allocation is marked by EXECUTE_READWRITE. Modify it to use READ_WRITE then EXECUTE_READ for better OPSEC. Add sleep functions, payload encryption, ect. 
