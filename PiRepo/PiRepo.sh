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
mkdir Command_And_Control
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
git clone https://github.com/FuzzySecurity/Dendrobate.git
git clone https://github.com/BC-SECURITY/Offensive-VBA-and-XLS-Entanglement.git
git clone https://github.com/aaaddress1/xlsGen.git
git clone https://github.com/bats3c/darkarmour.git
git clone https://github.com/outflanknl/InlineWhispers.git
git clone https://github.com/outflanknl/EvilClippy.git 
git clone https://github.com/fireeye/OfficePurge.git
git clone https://github.com/rasta-mouse/ThreatCheck.git
git clone https://github.com/gloxec/CrossC2.git 
git clone https://github.com/sensepost/ruler.git
git clone https://github.com/fireeye/DueDLLigence.git
git clone https://github.com/rasta-mouse/RuralBishop.git
git clone https://github.com/rasta-mouse/TikiTorch.git 
git clone https://github.com/mdsecactivebreach/SharpShooter.git
git clone https://github.com/cobbr/SharpSploit.git
git clone https://github.com/rvrsh3ll/MSBuildAPICaller.git
git clone https://github.com/sevagas/macro_pack.git
git clone https://github.com/klezVirus/inceptor.git
git clone https://github.com/0xsp-SRD/mortar.git

echo "Cloning Delivery Resources"

cd ../Delivery
git clone https://github.com/mdsecactivebreach/o365-attack-toolkit.git
git clone https://github.com/kgretzky/evilginx2.git
git clone https://github.com/gophish/gophish.git
git clone https://github.com/fireeye/PwnAuth.git
git clone https://github.com/drk1wi/Modlishka.git
git clone https://github.com/beefproject/beef.git

echo "Cloning Your C2 Resources"

cd ../Command_And_Control

echo "Cloning C2 Frameworks"

mkdir C2_Frameworks
cd C2_Frameworks
git clone https://github.com/BC-SECURITY/Empire.git
git clone https://github.com/nettitude/PoshC2.git
git clone https://github.com/zerosum0x0/koadic.git
git clone https://github.com/Ne0nd0g/merlin.git
git clone https://github.com/its-a-feature/Mythic.git
git clone https://github.com/cobbr/Covenant.git
git clone https://github.com/bats3c/shad0w.git
git clone https://github.com/BishopFox/sliver.git
git clone https://github.com/byt3bl33d3r/SILENTTRINITY.git
git clone https://github.com/n1nj4sec/pupy.git

echo "Cloning Staging Resources"

cd ../
mkdir Staging
cd Staging

git clone https://github.com/kgretzky/pwndrop.git
git clone https://github.com/FortyNorthSecurity/C2concealer.git
git clone https://github.com/rvrsh3ll/FindFrontableDomains.git
git clone https://github.com/threatexpress/domainhunter.git
git clone https://github.com/mgeeky/RedWarden.git
git clone https://github.com/Flangvik/AzureC2Relay.git
git clone https://github.com/FSecureLABS/C3.git
git clone https://github.com/mdsecactivebreach/Chameleon.git
git clone https://github.com/0xZDH/redirect.rules.git 

echo "Cloning Log Aggregation Resources"

cd ../
mkdir Log_Aggregation
cd Log_Aggregation

git clone https://github.com/outflanknl/RedELK.git
git clone https://github.com/SecurityRiskAdvisors/RedTeamSIEM.git

echo "Cloning Situational Awareness Resources"

cd /Repo/Situational_Awareness

mkdir Host_Situtational_Awareness
cd Host_Situational_Awareness

git clone https://github.com/EncodeGroup/AggressiveProxy.git
git clone https://github.com/EncodeGroup/Gopher.git
git clone https://github.com/PwnDexter/SharpEDRChecker.git
git clone https://github.com/trustedsec/CS-Situational-Awareness-BOF.git
git clone https://github.com/GhostPack/Seatbelt.git
git clone https://github.com/vivami/SauronEye.git
git clone https://github.com/mitchmoser/SharpShares.git
git clone https://github.com/Flangvik/SharpAppLocker/.git
git clone https://github.com/rvrsh3ll/SharpPrinter.git

cd ../Domain_Situational_Awareness

git clone https://github.com/FuzzySecurity/StandIn.git
git clone https://github.com/outflanknl/Recon-AD.git
git clone https://github.com/BloodHoundAD/BloodHound.git
git clone https://github.com/GhostPack/PSPKIAudit.git
git clone https://github.com/tevora-threat/SharpView.git
git clone https://github.com/GhostPack/Rubeus.git
git clone https://github.com/l0ss/Grouper.git
git clone https://github.com/improsec/ImproHound.git
git clone https://github.com/adrecon/ADRecon.git
git clone https://github.com/bats3c/ADCSPwn.git

cd /Repo/Credential_Dumping/

git clone https://github.com/gentilkiwi/mimikatz.git
git clone https://github.com/outflanknl/Dumpert.git
git clone https://github.com/xforcered/CredBandit.git
git clone https://github.com/xforcered/CredBandit.git
git clone https://github.com/swisskyrepo/SharpLAPS.git
git clone https://github.com/GhostPack/SharpDPAPI.git
git clone https://github.com/GhostPack/KeeThief.git
git clone https://github.com/GhostPack/SafetyKatz.git
git clone https://github.com/Barbarisch/forkatz.git
git clone https://github.com/RedCursorSecurityConsulting/PPLKiller.git
git clone https://github.com/AlessandroZ/LaZagne.git
git clone https://github.com/hoangprod/AndrewSpecial.git
git clone https://github.com/outflanknl/Net-GPPPassword.git
git clone https://github.com/djhohnstein/SharpChromium.git
git clone https://github.com/rxwx/chlonium.git
git clone https://github.com/chrismaddalena/SharpCloud.git
git clone https://github.com/skelsec/pypykatz.git
git clone https://github.com/helpsystems/nanodump.git

echo "Cloning Privilege Escallation Resources"

cd /Repo/Privilege_Escallation

git clone https://github.com/rsmudge/ElevateKit.git
git clone https://github.com/rasta-mouse/Watson.git
git clone https://github.com/GhostPack/SharpUp.git
git clone https://github.com/hlldz/dazzleUP.git
git clone https://github.com/carlospolop/PEASS-ng.git
git clone https://github.com/CCob/SweetPotato.git
git clone https://github.com/S3cur3Th1sSh1t/MultiPotato.git

cd /Repo/Defense_Evasion

git clone https://github.com/hlldz/RefleXXion.git
git clone https://github.com/wavestone-cdt/EDRSandblast.git
git clone https://github.com/APTortellini/unDefender.git
git clone https://github.com/Yaxser/Backstab.git
git clone https://github.com/boku7/spawn.git
git clone https://github.com/CCob/BOF.NET.git
git clone https://github.com/Flangvik/NetLoader.git
git clone https://github.com/outflanknl/FindObjects-BOF.git
git clone https://github.com/GetRektBoy724/SharpUnhooker.git
git clone https://github.com/bats3c/EvtMute.git
git clone https://github.com/xforcered/InlineExecute-Assembly.git
git clone https://github.com/hlldz/Phant0m.git 
git clone https://github.com/CCob/SharpBlock.git
git clone https://github.com/Kharos102/NtdllUnpatcher.git
git clone https://github.com/bats3c/DarkLoadLibrary.git 
git clone https://github.com/Soledge/BlockEtw.git
git clone https://github.com/mdsecactivebreach/firewalker.git
git clone https://github.com/Cerbersec/KillDefenderBOF.git

cd /Repos/Privilege_Escallation

git clone https://github.com/0xthirteen/SharpStay.git
git clone https://github.com/fireeye/SharPersist.git
git clone https://github.com/outflanknl/SharpHide.git
git clone https://github.com/Ben0xA/DoUCMe.git 
git clone https://github.com/nccgroup/ABPTTS.git 
git clone https://github.com/blackarrowsec/pivotnacci.git
git clone https://github.com/sensepost/reGeorg.git
git clone https://github.com/HarmJ0y/DAMP.git
git clone https://github.com/0x09AL/IIS-Raid.git
git clone https://github.com/antonioCoco/SharPyShell.git


