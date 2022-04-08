InsideMan is an internal Windows phishing executable that utilizes Powershell Get-Credential calls in an attempt to coerce the user into typing thier plaintext password into the prompt. The plaintext password is then written to a file named windows32.txt located in the user's Documents directory. 

USAGE:

Use gcc to compile the cpp file. gcc.exe insideman.cpp -o insideman.exe
