![Screen Shot 2022-10-02 at 10 29 43 AM](https://user-images.githubusercontent.com/76174163/193459711-647f63a7-b7e6-49b6-9659-f63cebdbeece.png)


Meet Harriet!

Harriet was inspired by the Charlotte C++ shellcode loader. This tool uses AES encryption and function/variable obfuscation to get around AV and Windows Defender.

<img width="779" alt="Screen Shot 2022-10-01 at 4 52 22 PM" src="https://user-images.githubusercontent.com/76174163/193458862-256141c2-7696-40aa-a272-c7db0635c453.png">

 At the time of writing, this is only detected by 1 vendor per AntiScan.me and will give you an undetected Meterpreter reverse shell. As we all know, Meterpreter is heavily signatured so you will have to play with the features (getsystem, hashdump,ect) to see what gets caught and what doesn't. 

There is no fancy process injection, it's just a straight AES encrypted executable. I will be working to implement other templates into the script in the future.  
 
The majority of this script was taken from the Sektor 7 Malware Development course. All credit goes to reenz0h and @Sektor7net. I wrote this mainly as a way to get a quick undetected executable for testing and to not have to switch over to a Windows VM every five seconds for compiling. 

Enjoy and don't upload to Virus Total!!!!!
