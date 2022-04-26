#!/bin/bash

cd /home/pi

echo "Updating Your System"
apt-get update -y && apt-get upgrade -y 
apt update -y && apt upgrade -y
apt autoremove -y
echo ""
echo "Installing System Dependencies"
echo ""
apt install git docker.io golang python3 python3-pip pipx chromium-browser -y
/usr/bin/python3 -m pip install --upgrade pip
echo "Removing Unneeded Directories"
rm -rf Videos/
rm -rf Music/
rm -rf Public/
rm -rf Templates/
echo""
echo "Installing Hackery Stuff"
apt install nmap amass recon-ng  -y
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
mkdir Social_Engineering
mkdir Phishing
mkdir Persistence
mkdir Lateral_Movement
mkdir Exfiltration
mkdir Cloud
mkdir Payload_Development
mkdir Hak5_Implants
mkdir Wireless
echo""
echo "Getting Resources"
sleep 2
echo""
echo "Cloning Recon Resources"
echo""
cd Recon
echo""
echo "Installing RustScan"
echo""
git clone https://github.com/RustScan/RustScan.git
cd RustScan.git
docker build -t rustscan .
cd ../
echo "Installing GitLeaks"
echo ""
git clone https://github.com/zricethezav/gitleaks.git
cd gitleaks/
make build
cd ../
echo ""
cd ../
echo "Installing S3Scanner"
echo ""
git clone https://github.com/sa7mon/S3Scanner.git
cd S3Scanner/
pip3 install -r requirements.txt
python3 -m S3Scanner
cd ../
echo""
echo "Installing Cloud_Enum"
echo""
git clone https://github.com/initstring/cloud_enum.git
cd cloud_enum
pip3 install -r ./requirements.txt
cd ../
echo "Installing Buster"
echo ""
git clone https://github.com/sham00n/buster.git
cd buster/
python3 setup.py install
cd ../
git clone https://github.com/initstring/linkedin2username.git 
echo ""
echo "Installing WitnessMe"
python3 -m pip install --user pipx
pipx install witnessme
pipx ensurepath
cd ../
echo ""
echo "Installing Pagodo"
echo ""
git clone https://github.com/opsdisk/pagodo.git
cd pagodo
pip install -r requirements.txt
cd ../
echo ""
echo "Installing AttackSurfaceMapper"
echo""
git clone https://github.com/superhedgy/AttackSurfaceMapper.git
cd AttackSurfaceMapper
python3 -m pip install --no-cache-dir -r requirements.txt
cd ../
echo ""
echo "Installing SpiderFoot"
echo ""
git clone https://github.com/smicallef/spiderfoot.git
cd spiderfoot
pip3 install -r requirements.txt
pip3 install cherrypy
pip3 install cherrypy_cors
pip3 install publicsuffixlist
pip3 install networkx
pip3 install openpyxl
cd ../
echo""
echo "Installing DNScan"
echo ""
git clone https://github.com/rbsec/dnscan.git
cd dnscan
pip3 install -r requirements.txt
pip3 install setuptools
cd ../
echo""
echo "Installing SpoofCheck"
echo""
git clone https://github.com/BishopFox/spoofcheck.git
cd spoofcheck
pip3 install -r requirements.txt
echo ""
echo "Installing LinkedInt"
echo""
git clone https://github.com/vysecurity/LinkedInt.git
cd LinkedInt
pip3 install -r requirements.txt
echo ""
echo "Installing EyeWitness"
git clone https://github.com/ChrisTruncer/EyeWitness.git
cd EyeWitness/Python/setup
bash setup.sh
cd /opt/Recon/
echo""
echo "Installing Aquatone"
echo ""
wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
unzip aquatone_linux_amd64_1.7.0.zip
cd ../
echo""
echo "Installing DNSrecon"
git clone https://github.com/darkoperator/dnsrecon.git
echo ""

git clone https://github.com/SpiderLabs/social_mapper.git
git clone https://github.com/xillwillx/skiptracer.git
git clone https://github.com/dchrastil/ScrapedIn.git
git clone https://github.com/NickSanzotta/linkScrape.git
git clone https://github.com/ElevenPaths/FOCA
git clone https://github.com/laramies/theHarvester.git
git clone https://github.com/laramies/metagoofil.git
git clone https://github.com/killswitch-GUI/SimplyEmail.git
git clone https://github.com/dxa4481/truffleHog.git
git clone https://github.com/ChrisTruncer/Just-Metadata.git
git clone https://github.com/nccgroup/typofinder.git
git clone https://github.com/thewhiteh4t/pwnedOrNot.git
git clone https://github.com/metac0rtex/GitHarvester.git

echo "Cloning Initial Access Resources"
cd ../Initial_Access
git clone https://github.com/byt3bl33d3r/SprayingToolkit.git
git clone https://github.com/nyxgeek/o365recon.git
git clone https://github.com/blacklanternsecurity/TREVORspray.git

echo "Cloning Payload Development Resources"

cd ../Payload_Development

git clone https://github.com/trustedsec/unicorn.git
git clone https://github.com/nccgroup/demiguise.git
git clone https://github.com/secretsquirrel/the-backdoor-factory.git
git clone https://github.com/govolution/avet.git
git clone https://github.com/threatexpress/metatwin.git
git clone https://github.com/cobbr/PSAmsi.git
git clone https://github.com/3gstudent/Worse-PDF.git
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
git clone https://github.com/Mr-Un1k0d3r/RedTeamCCode.git

echo "Cloning Delivery Resources"

cd ../Delivery
git clone https://github.com/mdsecactivebreach/o365-attack-toolkit.git
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
sudo apt-get install build-essential libreadline-dev libssl-dev libpq5 libpq-dev libreadline5 libsqlite3-dev libpcap-dev subversion git-core autoconf postgresql pgadmin3 curl zlib1g-dev libxml2-dev libxslt1-dev libyaml-dev nmap -y
sudo curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall

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

cd /home/pi/Repo/Situational_Awareness
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

cd ../
mkdir Domain_Situational_Awareness
cd Domain_Situational_Awareness

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

cd /home/pi/Repo/Credential_Dumping/

git clone https://github.com/gentilkiwi/mimikatz.git
git clone https://github.com/outflanknl/Dumpert.git
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

cd /home/pi/Repo/Privilege_Escallation

git clone https://github.com/rsmudge/ElevateKit.git
git clone https://github.com/rasta-mouse/Watson.git
git clone https://github.com/GhostPack/SharpUp.git
git clone https://github.com/hlldz/dazzleUP.git
git clone https://github.com/carlospolop/PEASS-ng.git
git clone https://github.com/CCob/SweetPotato.git
git clone https://github.com/S3cur3Th1sSh1t/MultiPotato.git

echo "Cloning Defense Evasion Resources"

cd /home/pi/Repo/Defense_Evasion

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

echo "Cloning Social Engineering Resources"

cd /home/pi/Social_Engineering
git clone https://github.com/trustedsec/social-engineer-toolkit.git
git clone https://github.com/bhdresh/SocialEngineeringPayloads.git


echo "Cloning Phishing Resources"

cd /home/pi/Phishing
git clone https://github.com/ryhanson/phishery.git
git clone https://github.com/kgretzky/evilginx2.git
git clone https://github.com/fireeye/PwnAuth.git
git clone https://github.com/drk1wi/Modlishka.git
git clone https://github.com/securestate/king-phisher.git
git clone https://github.com/Raikia/FiercePhish.git
git clone https://github.com/fireeye/ReelPhish.git
git clone https://github.com/gophish/gophish.git
git clone https://github.com/ustayready/CredSniper.git
git clone https://github.com/pentestgeek/phishing-frenzy.git
git clone https://github.com/L4bF0x/PhishingPretexts.git

echo "Cloning Persistence Resources"

cd /home/pi/Repo/Persistence

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

echo "Cloning Lateral Movement Resources"

cd /home/pi/Repo/Lateral_Movement

git clone https://github.com/RiccardoAncarani/LiquidSnake.git
git clone https://github.com/NetSPI/PowerUpSQL.git
git clone https://github.com/0xthirteen/SharpRDP.git
git clone https://github.com/0xthirteen/MoveKit.git
git clone https://github.com/juliourena/SharpNoPSExec.git
git clone https://github.com/lgandx/Responder.git
git clone https://github.com/dirkjanm/mitm6.git
git clone https://github.com/SecureAuthCorp/impacket.git
git clone https://github.com/mdsecactivebreach/Farmer.git
git clone https://github.com/FortyNorthSecurity/CIMplant.git
git clone https://github.com/Mr-Un1k0d3r/PowerLessShell.git
git clone https://github.com/FSecureLABS/SharpGPOAbuse.git
git clone https://github.com/ropnop/kerbrute.git 
git clone https://github.com/blackarrowsec/mssqlproxy.git
git clone https://github.com/Kevin-Robertson/Invoke-TheHash.git
git clone https://github.com/Kevin-Robertson/InveighZero.git
git clone https://github.com/jnqpblc/SharpSpray/git
git clone https://github.com/byt3bl33d3r/CrackMapExec.git
git clone https://github.com/pkb1s/SharpAllowedToAct.git
git clone https://github.com/bohops/SharpRDPHijack.git
git clone https://github.com/klezVirus/CheeseTools.git
git clone https://github.com/iomoath/SharpSpray.git
git clone https://github.com/BloodHoundAD/SharpHound.git
git clone https://github.com/PowerShellMafia/PowerSploit.git
git clone https://github.com/NetSPI/PowerUpSQL.git
git clone https://github.com/DanMcInerney/icebreaker.git
git clone https://github.com/JavelinNetworks/HoneypotBuster.git
echo "Cloning Exfiltration Resources"

cd /home/pi/Repo/Exfiltration

git clone https://github.com/Flangvik/SharpExfiltrate.git
git clone https://github.com/Arno0x/DNSExfiltrator.git
git clone https://github.com/FortyNorthSecurity/Egress-Assess.git

echo "Cloning Cloud Resources"

cd /home/pi/Repo/Cloud

mkdir AWS
git clone https://github.com/RhinoSecurityLabs/pacu.git
git clone https://github.com/duo-labs/cloudmapper.git
git clone https://github.com/andresriancho/enumerate-iam.git
git clone https://github.com/jordanpotti/AWSBucketDump.git

cd ../
mkdir Azure
cd Azure

git clone https://github.com/fox-it/adconnectdump.git
git clone https://github.com/Azure/Stormspotter.git
git clone https://github.com/dirkjanm/ROADtools.git
git clone https://github.com/NetSPI/MicroBurst.git
git clone https://github.com/Gerenios/AADInternals.git 

echo "Cloning Hak5 Implant Resources"

cd /home/pi/Repo/Hak5_Implants

git clone https://github.com/hak5/omg-payloads.git
git clone https://github.com/hak5/bashbunny-payloads.git
git clone https://github.com/hak5/usbrubberducky-payloads.git
git clone https://github.com/hak5/pineapple-community-packages.git
git clone https://github.com/hak5/pineapple-modules.git
git clone https://github.com/hak5/mk7-docs.git
git clone https://github.com/hak5/keycroc-payloads.git
git clone https://github.com/hak5/sharkjack-payloads.git
git clone https://github.com/hak5/lanturtle-modules.git
git clone https://github.com/hak5/hak5-docs.git
git clone https://github.com/hak5/packetsquirrel-payloads.git
git clone https://github.com/hak5/nano-tetra-modules.git
git clone https://github.com/hak5/signalowl-payloads.git
git clone https://github.com/hak5/plunderbug-scripts.git

echo "Cloning Wireless Resources"

cd /home/pi/Repo/Wireless

git clone https://github.com/derv82/wifite2.git
git clone https://github.com/wifiphisher/wifiphisher.git
git clone https://github.com/sensepost/mana.git
git clone https://github.com/joswr1ght/cowpatty.git
git clone https://github.com/athanstan/EvilTwin_AP_CaptivePortal.git
