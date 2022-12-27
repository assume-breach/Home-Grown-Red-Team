PiMPlant is a bash script that turns your Raspberry Pi Zero W into a network implant that automatically calls back to a C2 server through SSH. 

Tools installed with PiMPlant include Metasploit, Wifite, Responder, Impacket, Aquatone, DNSrecon, Mitm6, Medua, Macchanger, Nmap, Hashcat, Tmux, and Hydra.

More tools are added as I come across them. 

Usage:

1.) Set up a C2 droplet and enable SSH.

2.) Run bash PiMPlant.sh (run as pi user with sudo!!)

3.) Fill in the prompts.

4.) Reboot and connect to your implant on port 2222 on your C2 server: ssh -p 2222 pi@localhost
