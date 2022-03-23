#!/bin/bash

sudo su
cd /home/pi

echo "Updating Your System"
apt-get update -y && apt-get upgrade -y 
apt update -y && apt upgrade -y
apt autoremove -y

echo "Removing Unneeded Directories"
rm -rf Videos/
rm -rf Music/
rm -rf Public/
rm -rf Templates/

echo "Creating Repo Folders"
mkdir Repo
cd Repo
mkdir Initial_Access
mkdir Recon
mkdir Delivery
mkdir Situational_Awareness
mkdir Credential_Dumping
mkdir Privilege_Escallation
mkidr Defense_Evasion
mkdir Persistence
mkdir Lateral_Movement
mkdir Exfiltration
mkdir Miscellaneous
mkdir Payload_Development
mkdir Hak5_Implants

echo "Getting Resources"
sleep 2
echo "Cloning Recon Resources"
cd Recon
git clone https://github.com/RustScan/RustScan.git
git clone https://github.com/OWASP/Amass.git
git clone https://github.com/zricethezav/gitleaks.git
git clone https://github.com/sa7mon/S3Scanner.git
git clone https://github.com/initstring/cloud_enum.git
git clone https://github.com/lanmaster53/recon-ng.git
git clone https://github.com/sham00n/buster.git
git clone https://github.com/initstring/linkedin2username.git 
git clone https://github.com/byt3bl33d3r/WitnessMe/git
git clone https://github.com/opsdisk/pagodo.git
git clone https://github.com/superhedgy/AttackSurfaceMapper.git
git clone https://github.com/smicallef/spiderfoot.git
git clone https://github.com/rbsec/dnscan.git
git clone https://github.com/BishopFox/spoofcheck.git
git clone https://github.com/vysecurity/LinkedInt.git

echo "Cloning Initial Access Resources"
cd ../Initial_Access
git clone https://github.com/byt3bl33d3r/SprayingToolkit.git
git clone https://github.com/nyxgeek/o365recon.git
git clone https://github.com/blacklanternsecurity/TREVORspray.git

echo "Cloning Payload Development Resources"

cd ../Payload_Development
git clone https://github.com/optiv/Ivy.git
git clone https://github.com/phra/PEzor.git
git clone https://github.com/med0x2e/GadgetToJScript.git
git clone https://github.com/optiv/ScareCrow.git
git clone https://github.com/TheWover/donut.git
git clone https://github.com/D00MFist/Mystikal.git
git clone https://github.com/9emin1/charlotte.git
git clone https://github.com/xforcered/InvisibilityCloak.git
