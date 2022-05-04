AutoC2 is a bash script written to install all of the red team tools that you know and love. This can transform your Ubuntu/Linux Mint Virtual Machine into a Red Teaming development workstation! It takes a while to install everything so be patient.

Usage

1) Install Ubuntu 21.01 or Linux Mint on your computer. You can also install it as a VM on your computer, but remember to give your VM hypervisor rights.
2) Git clone the bash script or copy and paste it over to your instance.
3) Run the script: bash AutoC2.sh
4) Wait for the script to run and reboot your VM. Once rebooted, your new workstation should be good to go.
5) 

#Issues

There are some issues with software that is installed based on your release. For instance, Empire won't install on Linux Mint currently with the script. This is because the install script determines the version of the VM and Mint isn't on Empire's compatability list. For some software, you will have to go into the setup files and change the version to install. 98% of the tools and their dependencies will be automatically installed and will work out of box.

A lot of software does not work with the latest Ubuntu 22.04 version. For instance, VirtualBox does not have a version for 22.04 yet. I recommend using Ubuntu 21.10 for now until they get things up to date. 

If you run into an issue with a piece of software, open an issue or hit me up on twitter @assume_breach. Additionally, if you want more tools added to the script you can do the same!

#Software Installed

Go
Docker
Python3
Pipx
Pip3
Git
Chromium-browser
Wine 
Dnsmasq
Hostapd
Openssl 
Open-vm-tools-desktop
Build-essential
Net-tools
Snap 
Fuse
Make 
Dhcpd
Lighttpd
VirtualBox

#VMs

Kali Linux VirtualBox image
Windows 10 Development Image

#Documentation

CherryTree

#Recon

Nmap
AMASS
Recon-NG
RustScan
GitLeaks
S3Scanner
Cloud_Enum
Buster
WitnessMe
Pagodo
AttackSurfaceMapper
SpiderFoot
DNScan
SpoofCheck
LinkedInt
EyeWitness
Aquatone
DNSrecon
Social Mapper
theHarvester
Metagoofil
TruffleHog

#Initial Access

Spraying Toolkit
O365 Recon
TREVORspray

#Payload Development

Unicorn
Demiguise
The Backdoor Factory
Avet
MetaTwin
PSAmsi
Worse-PDF
Ivy
PEzor
GadgetToJScript
ScareCrow
Donut
Mystical
Invisibility Cloak
Denodrabe
Offensive VBA and XLS Entaglement
xlsGen
DarkArmour
InlineWhispers
EvilClippy
OfficePurge
ThreatCheck
Ruler
DueDLLigence
RuralBiship
TikiTorch
SharpShooter
SharpSploit
MSBuildAPICaller
Macro_Pack
Inceptor
Mortar
RedTeamCCode

#Delivery

O365 Attack Toolkit
Beef

#Command & Control Frameworks

Empire w/ Starkiller
PoshC2
Merlin
Mythic
Covenant
Shad0w
Sliver
SILENTTRINITY
Metasploit

#Staging

PwnDrop
C2Concealer
FindFrontableDomains
Domain hunter
RedWarden
AzureC2Relay
C3
Chameleon
Redirect.Rules

#Log Aggregation

RedELK
RedTeamSIEM

#Situational Awareness

AggressiveProxy
Gopher
SharpEDRChecker
CS Situational Awareness BOF
Seatbelt
SauronEye
SharpShares
SharpAppLOcker
SharpPrinter
Standin
Recon-AD
BloodHound
PSPKIAudit
Sharpview
Rubeus
Grouper
ImproHound
ADRecon
ADCSPwn

#Credential Dumping

Mimikatz
Dumpert
SharpLAPS
SharpDPAPI
KeeThief
SafetyKatz
Forkatz
PPLKiller
Lazagne
Andrew Special
Net-GPPassword
SharpChromium
Chlonium
SharpCloud
PypyKatz
NanoDump

#Privilege Escalation

ElevateKit
Watson
SharpUp
dazzleUp
PEASS-ng
SweetPotato
Multipotato

#Defense Evasion

RefleXXion
EDRSandblast
unDefender
Backstab
Spawn
BOF.NET
NetLoader
FindObject-BOFF
Sharpunhooker
EvtMute
InlineExecute-Assembly
Phant0m
SharpBlock
Ntdllunpatcher
DarkLoadLibrary
BlockEtw
Firewalker
KillDefenderBOF

#Social Engineering

Social Engineering Toolkit
Social Engineering Payloads

#Phishing

Phishery
Evilginx2
PwnAuth
Modlishka
KingPhisher
FiercePhish
ReelPhish
GoPhish
CredSniper
Phishing Pretexts

#Persistence

SharpStay
SharPersist
SharpHide
DoUCMe
ABPTTS
PivotNacci
ReGorge
DAMP
ISS-RAID
SharPyShell

#Lateral Movement

Responder
Mitm6
Impact
LiquidSnake
PowerUpSQL
MoveKit
SharpNoPSExec
Farmer
CIMplant
PowerLessShell
SharpGPOAbuse
Kerbrute
Mssqlproxy
Invoke-TheHash
InveighZero
SharpSpray
CrackMapExec
SharpHound
PowerSploit
SharpAllowedToAct
SharpRDPHijack
CheeseTools
IceBreaker
HoneypotBuster

#Exfiltration

SharpExfiltrate
DNSExfiltrator
Egress-Assess

#Web

Nikto
Wfuzz
Dirb
Sqlmap
WPscan

#Cloud

#AWS

Pacu
CloudMapper
Enumerate-IAM
AWSBucketDump

#Azure

ADConnectDump
StormSpotter
ROADTools
MicroBurst
AADInternals

#Password Cracking

Medusa
Crunch
Mewl
Hydra
Ncrack

#Wordlists & Rule Sets

Hob0Rules
SecLists
RockYou
Password_Cracking_Rules

#Hak5 Payloads

OMG payloads
BashBunny Payloads
USB Rubber Ducky Payloads
Pineapple Community Packages
Pineapple Modules
Mark 7 Documents
KeyCroc Payloads
SharkJack Payloads
LanTurtle Modules
Hak5 Documents
Packet Squirrel Payloads
Pineapple Tetra Modules
Signal Owl Payloads
Plunderbug scripts


#Wireless

BeRateAP
Wifite
Mdk4
Mdk3
Dsniff 
Aircrack-ng
Ettercap 
Macchanger
EvilTwin Captive Portal
Fluxion
Airgeddon
HCXTools
Eaphammer
Bully

#Wireless Drivers 

RTL8812AU

