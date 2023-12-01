![Screenshot 2023-11-29 at 1 43 30 PM](https://github.com/assume-breach/Home-Grown-Red-Team/assets/76174163/b88fe959-5b3c-4b14-98a0-24b6c6f5b3e1)

StageFright is a staged payload framework that allows the user to run customized staged payloads over various protocols. The framework is based on my blog article found here: https://medium.com/@assume-breach/home-grown-red-team-hosting-encrypted-stager-shellcode-1dc5e06eaeb3

Right now, the only protocols in the framework are SMB and TCP. More will be available in the future; ie http/https.

At this time, the tool will give you both DLLs and EXEs. All EXEs and DLLs are signed using SigThief. This seems to cut down on some alerts in Microsoft Defender For Endpoint.

This is a replacement for the Shareable tool I uploaded a little while ago. Eventually, this tool will be merged into the Harriet tool, but for now, this is what I have finished. You can watch out for updates on Twitter as I will tweet out when new features and things have been added.

How To Use

bash StageFright.sh

Go through the menus and select your stager. 

![Screenshot 2023-11-29 at 1 54 06 PM](https://github.com/assume-breach/Home-Grown-Red-Team/assets/76174163/316dcf6a-fa2c-48f5-8198-b01f00315fd1)

SMB Stager

For SMB enter the values for the share/shared folder that is writable. 

![Screenshot 2023-11-29 at 1 55 41 PM](https://github.com/assume-breach/Home-Grown-Red-Team/assets/76174163/dac1031c-b238-49bb-9280-9268e6582559)

Upload your shellcode file to the share/shared folder.

![Screenshot 2023-11-29 at 1 56 51 PM](https://github.com/assume-breach/Home-Grown-Red-Team/assets/76174163/1bcd1a50-9452-45fd-af8c-a34e4dfaa1b9)

Run the tool. 

![Screenshot 2023-11-29 at 1 58 22 PM](https://github.com/assume-breach/Home-Grown-Red-Team/assets/76174163/e8318b29-9a3d-43aa-944f-4ffb4df017fa)

![Screenshot 2023-11-29 at 1 58 54 PM](https://github.com/assume-breach/Home-Grown-Red-Team/assets/76174163/af11eac6-2e2a-4d69-92d4-6e974260997d)

If you get onto another machine on the network that has access to the shared/shared folder you can retrieve the shellcode file and get a beacon. I ran the tool on my DC which has access to the shared folder. 

![Screenshot 2023-11-29 at 2 01 04 PM](https://github.com/assume-breach/Home-Grown-Red-Team/assets/76174163/f90ba02d-ca6c-447d-91e7-0960aa4f2fae)

![Screenshot 2023-11-29 at 2 01 22 PM](https://github.com/assume-breach/Home-Grown-Red-Team/assets/76174163/ba44db8f-7ce5-443d-8890-313b02c42467)

TCP Stager

Go through the script.

![Screenshot 2023-11-29 at 2 04 04 PM](https://github.com/assume-breach/Home-Grown-Red-Team/assets/76174163/76ff0178-f8b8-4b6b-9905-dbedde578275)

You will have to host the TCP server. I have provided a python script to spin this up. You can find it in StageFright/StageFright/TCP. As of right now the script does not replace the values in the python script (it will over the next couple of days) so you will need to replace those values by hand. 

![Screenshot 2023-11-29 at 2 06 21 PM](https://github.com/assume-breach/Home-Grown-Red-Team/assets/76174163/8f26a283-045f-4ece-9b8f-c474c2e37e49)

Run the script to start the TCP server.

![Screenshot 2023-11-29 at 2 08 03 PM](https://github.com/assume-breach/Home-Grown-Red-Team/assets/76174163/1b218e01-18a2-41d9-ad05-19a5ced4e12d)

Transfer the EXE stager to the target and execute.

![Screenshot 2023-11-29 at 2 10 04 PM](https://github.com/assume-breach/Home-Grown-Red-Team/assets/76174163/d3cd2371-d869-4112-8115-584ec27ee31b)

![Screenshot 2023-11-29 at 2 10 25 PM](https://github.com/assume-breach/Home-Grown-Red-Team/assets/76174163/0882b329-ff59-41ea-ab5b-85f194a0de53)

![Screenshot 2023-11-29 at 2 10 35 PM](https://github.com/assume-breach/Home-Grown-Red-Team/assets/76174163/dec8fa57-3fee-49ac-a1a6-845660072854)

Everything should work out of box on Kali but for Mint/Ubuntu you will need to install MingW64 for compilation. This is the beginning of the project. Mainly releasing this so I have a base to go off of. No OPSEC considerations have been made at this time. Native APIs are used in some cases. Whatever AV/EDR that this gets past at this point is unknown. It will get past Defender and MDE (P1 trial license) with no alerts.  


