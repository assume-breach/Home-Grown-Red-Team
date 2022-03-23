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
