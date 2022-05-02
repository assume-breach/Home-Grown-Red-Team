#!/bin/bash
cat << "EOF"
  __ _ ___ ___ _   _ _ __ ___   ___      | |__  _ __ ___  __ _  ___| |__  
 / _` / __/ __| | | | '_ ` _ \ / _ \_____| '_ \| '__/ _ \/ _` |/ __| '_ \ 
| (_| \__ \__ \ |_| | | | | | |  __/_____| |_) | | |  __/ (_| | (__| | | |
 \__,_|___/___/\__,_|_| |_| |_|\___|     |_.__/|_|  \___|\__,_|\___|_| |_|
                            
                                **AutoC2**
                                
                          Use At Your Own Risk
               
                   
 
EOF
sleep 2
echo""
echo""
echo           "WARNING THIS SCRIPT TAKES FUCKING FOREVER!!!"
echo""
echo""
echo           "All Tools Can Be Found In The /opt Directory"
echo ""
sleep 2
read -p "Press enter to continue"
echo ""
echo "Updating Your System"
echo""
sleep 2
apt-get update -y && apt-get upgrade -y 
apt update -y && apt upgrade -y
apt autoremove -y
echo ""
sleep 2
echo "Installing System Dependencies"
echo ""
sleep 2
apt install git -y
apt install docker.io golang python-pip python3 make snap fuse ruby-bundler python3-pip pipx chromium-browser dnsmasq hostapd openssl open-vm-tools-desktop build-essential libpcap-dev net-tools -y
/usr/bin/python3 -m pip install --upgrade pip
echo ""
echo "Installing Hackery Stuff"
echo ""
sleep 2
apt install nmap wifite hcxtools aircrack-ng ettercap-graphical john hashcat crunch tshark macchanger recon-ng snap dhcpd 7zip lighttpd mdk4 dsniff mdk3 php-cgi xterm cewl crunch hydra sqlmap ncrack gobuster dirb wfuzz medusa netcat -y
snap install amass
echo ""
sleep 2
echo "Installing CherryTree For Documentation"
sleep 3
sudo apt-get install cherrytree -y
apt --fix-broken install -y
echo ""
echo "Creating Tool Folders"
echo ""
sleep 2
cd /opt
mkdir Initial_Access
mkdir Recon
mkdir Command_And_Control
mkdir Social_Engineering
mkdir Phishing
mkdir Delivery
mkdir Lateral_Movement
mkdir Cloud
mkdir Payload_Development
mkdir Hak5_Implants
mkdir Wireless
mkdir Wordlists
mkdir Virtual_Machines
mkdir Staging
mkdir Log_Aggregation
mkdir Windows_OS
echo""
echo "Getting Resources"
sleep 2
echo ""
echo "Installing Wordlists & Rule Sets"
sleep 3
cd /opt/Wordlists/
git clone https://github.com/NotSoSecure/password_cracking_rules.git
git clone https://github.com/praetorian-inc/Hob0Rules.git
git clone https://github.com/danielmiessler/SecLists.git
echo""
echo "Installing Recon Resources"
echo""
sleep 2
cd /opt/Recon/
echo""
echo "Installing RustScan"
echo""
sleep 2
git clone https://github.com/RustScan/RustScan.git
cd RustScan.git
docker build -t rustscan .
cd /opt/Recon/
echo "Installing GitLeaks"
echo ""
sleep 2
git clone https://github.com/zricethezav/gitleaks.git
cd gitleaks/
make build
echo ""
cd /opt/Recon/
echo "Installing S3Scanner"
echo ""
sleep 2
git clone https://github.com/sa7mon/S3Scanner.git
cd S3Scanner/
pip3 install -r requirements.txt
python3 -m S3Scanner
cd /opt/Recon/
echo""
echo "Installing Enum4Linux"
cd /opt/Recon/
echo ""
sleep 2
git clone https://github.com/CiscoCXSecurity/enum4linux.git
echo "alias enum4linux='/opt/enum4linux/./enum4linux.pl'" >> /root/.bashrc
echo ""
echo "Installing Cloud_Enum"
echo""
sleep 2
git clone https://github.com/initstring/cloud_enum.git
cd cloud_enum
pip3 install -r ./requirements.txt
cd /opt/Recon/
echo "Installing Buster"
echo ""
sleep 2
git clone https://github.com/sham00n/buster.git
cd buster/
python3 setup.py install
cd /opt/Repo/
git clone https://github.com/initstring/linkedin2username.git 
echo ""
echo "Installing WitnessMe"
echo ""
sleep 2
python3 -m pip install --user pipx
pipx install witnessme
pipx ensurepath
cd /opt/Recon/
echo ""
echo "Installing Pagodo"
echo ""
sleep 2
git clone https://github.com/opsdisk/pagodo.git
cd pagodo
pip install -r requirements.txt
cd /opt/Recon/
echo ""
echo "Installing AttackSurfaceMapper"
echo""
sleep 2
git clone https://github.com/superhedgy/AttackSurfaceMapper.git
cd AttackSurfaceMapper
python3 -m pip install --no-cache-dir -r requirements.txt
cd /opt/Recon/
echo ""
echo "Installing SpiderFoot"
echo ""
sleep 2
git clone https://github.com/smicallef/spiderfoot.git
cd spiderfoot
pip3 install -r requirements.txt
pip3 install cherrypy
pip3 install cherrypy_cors
pip3 install publicsuffixlist
pip3 install networkx
pip3 install openpyxl
cd /opt/Recon/
echo""
echo "Installing DNScan"
echo ""
sleep 2
git clone https://github.com/rbsec/dnscan.git
cd dnscan
pip3 install -r requirements.txt
pip3 install setuptools
cd /opt/Recon/
echo""
echo "Installing SpoofCheck"
echo""
sleep 2
git clone https://github.com/BishopFox/spoofcheck.git
cd spoofcheck
pip3 install -r requirements.txt
cd /opt/Recon/
echo ""
echo "Installing LinkedInt"
echo""
sleep 2
git clone https://github.com/vysecurity/LinkedInt.git
cd LinkedInt
pip3 install -r requirements.txt
cd /opt/Recon/
echo ""
echo "Installing EyeWitness"
echo ""
sleep 2
git clone https://github.com/ChrisTruncer/EyeWitness.git
cd EyeWitness/Python/setup
bash setup.sh
cd /opt/Recon/
echo""
echo "Installing Aquatone"
echo ""
sleep 2
mkdir Aquatone
cd Aquatone/
wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
unzip aquatone_linux_amd64_1.7.0.zip
cd /opt/Recon/
echo""
echo "Installing DNSrecon"
echo ""
sleep 2
git clone https://github.com/darkoperator/dnsrecon.git
cd dnsrecon
pip install -r requirements.txt
python setup.py install
cd /opt/Recon/
echo ""
echo "Installing Social Mapper"
echo ""
sleep 2
git clone https://github.com/SpiderLabs/social_mapper.git
cd /social_mapper/setup/
pip install -r requirements.txt
echo""
cd /opt/Recon/
echo "Installing theHarvester"
echo ""
sleep 2
git clone https://github.com/laramies/theHarvester.git
cd theHarvester/
pip3 install aiohttp
pip3 install aiomultiprocess
python3 -m pip install -r requirements/base.txt
python3 setup.py install
cd /opt/Recon/
echo ""
echo "Installing Metagoofil"
echo ""
sleep 2
git clone https://github.com/laramies/metagoofil.git
echo""
echo "Installing TruffleHog"
echo ""
sleep 2
git clone https://github.com/dxa4481/truffleHog.git
cd trufflehog; go install
cd /opt/Recon/
echo""
echo "Installing Pwned0rNot -- API KEY REQUIRE"
git clone https://github.com/thewhiteh4t/pwnedOrNot.git
cd pwnedOrNot
chmod +x install.sh
./install.sh
cd /opt/Recon/
echo""
echo "Installing GitHarvester"
echo ""
sleep 2
git clone https://github.com/metac0rtex/GitHarvester.git
echo ""
echo "Cloning Initial Access Resources"
echo ""
sleep 2

###Break For Recon Folder###

cd /opt/Initial_Access
echo "Installing Initial Access Tools"
echo ""
sleep 2
echo "Installing Spraying Toolkit"
echo ""
sleep 2
git clone https://github.com/byt3bl33d3r/SprayingToolkit.git
cd SprayingToolkit/
pip3 install -r requirements.txt
cd /opt/Initial_Access
echo ""
sleep 2
echo "Installing O365 Recon"
echo ""
git clone https://github.com/nyxgeek/o365recon.git
echo ""
sleep 2
echo "Installing TREVORspray"
echo ""
sleep 2
git clone https://github.com/blacklanternsecurity/TREVORspray.git
cd TREVORspray/
pip3 install -r requirements.txt
sleep 2

###Break Initial Access###

echo ""
echo "Installing Payload Development Resources"
echo ""
sleep 2
cd /opt/Payload_Development
echo "Installing Unicorn"
git clone https://github.com/trustedsec/unicorn.git
echo""
echo "Installing Demiguise"
echo ""
sleep 2
git clone https://github.com/nccgroup/demiguise.git
echo ""
echo "Installing The Backdoor Factory"
echo ""
docker pull secretsquirrel/the-backdoor-factory
echo ""
sleep 2
echo "Installing Avet"
echo ""
git clone https://github.com/govolution/avet.git
cd avet
bash setup.sh
cd /opt/Payload_Development/
sleep 2
echo ""
echo "Installing MetaTwin"
git clone https://github.com/threatexpress/metatwin.git
echo ""
sleep 2
echo "Installing PSAmsi"
git clone https://github.com/cobbr/PSAmsi.git
sleep 2
echo ""
echo "Worse-PDF"
echo ""
git clone https://github.com/3gstudent/Worse-PDF.git
echo ""
sleep 2
echo "Installing Ivy"
echo ""
git clone https://github.com/optiv/Ivy.git
cd Ivy
go get github.com/fatih/color
go get github.com/KyleBanks/XOREncryption/Go
go build Ivy.go
echo ""
cd /opt/Payload_Development/
echo "Installing PEzor"
echo ""
git clone https://github.com/phra/PEzor.git
cd PEzor/
bash install.sh
echo ""
#read -p "Open A New Terminal And Export The Path For PEzor To Work!"
echo ""
sleep 2
echo "Installing ScareCrow"
echo""
cd /opt/Payload_Development/
git clone https://github.com/optiv/ScareCrow.git
cd ScareCrow/
go get github.com/fatih/color
go get github.com/yeka/zip
go get github.com/josephspurrier/goversioninfo
apt install openssl -y
apt install osslsigncode -y
apt install mingw-w64 -y
go build ScareCrow.go
cd /opt/Payload_Development/
echo ""
sleep 2
echo "Installing Donut"
echo ""
git clone https://github.com/TheWover/donut.git
cd donut/
python3 setup.py install
cd /opt/Payload_Development
mkdir MAC_OS
cd MAC_OS
echo ""
sleep 2
echo "Installing Mystikal"
echo ""
git clone https://github.com/D00MFist/Mystikal.git
cd /opt/Payload_Development/
echo ""
sleep 2
cd /opt/Windows_OS
echo "Installing GadgetToJscript"
git clone https://github.com/med0x2e/GadgetToJScript.git
echo ""
cd /opt/Payload_Development/
echo "Installing Charlotte"
git clone https://github.com/9emin1/charlotte.git
echo ""
cd /opt/Payload_Development/
echo "Installing Invisibility Cloak"
git clone https://github.com/xforcered/InvisibilityCloak.git
echo ""
cd /opt/Windows_OS/
echo "Installing Dendrobate"
echo ""
git clone https://github.com/FuzzySecurity/Dendrobate.git
echo ""
sleep 2
cd /opt/Payload_Development/
echo "Installing Offensive-VBA-and-XLS-Entanglement"
echo ""
git clone https://github.com/BC-SECURITY/Offensive-VBA-and-XLS-Entanglement.git
sleep 2
echo ""
echo "Installing xlsGen"
echo ""
sleep 2
git clone https://github.com/aaaddress1/xlsGen.git
echo ""
echo "Installing DarkArmour"
echo ""
sleep 2
git clone https://github.com/bats3c/darkarmour.git
sudo apt install mingw-w64-tools mingw-w64-common g++-mingw-w64 gcc-mingw-w64 upx-ucl osslsigncode -y
echo ""
echo "Installing InlineWhispers"
echo""
sleep 2
git clone https://github.com/outflanknl/InlineWhispers.git
echo ""
cd /opt/Windows_OS/
echo "Installing EvilClippy"
echo ""
sleep 2
git clone https://github.com/outflanknl/EvilClippy.git 
echo ""
echo "Installing OfficePurge"
echo ""
git clone https://github.com/fireeye/OfficePurge.git
sleep 2
echo ""
echo "Installing ThreatCheck"
echo ""
git clone https://github.com/rasta-mouse/ThreatCheck.git
echo ""
echo "Ruler"
echo ""
sleep 2
git clone https://github.com/sensepost/ruler.git
echo ""
echo "Installing DueDLLigence"
echo ""
sleep 2
git clone https://github.com/fireeye/DueDLLigence.git
echo ""
echo "Installing RuralBishop"
echo ""
sleep 2
git clone https://github.com/rasta-mouse/RuralBishop.git
echo ""
echo "Installing TikiTorch"
echo ""
sleep 2
git clone https://github.com/rasta-mouse/TikiTorch.git 
echo ""
echo "Installing SharpShooter"
echo ""
sleep 2
git clone https://github.com/mdsecactivebreach/SharpShooter.git
echo ""
echo "Installing SharpSploit"
echo ""
sleep 2
git clone https://github.com/cobbr/SharpSploit.git
echo ""
echo "Installing MSBuildAPICaller"
echo ""
sleep 2
git clone https://github.com/rvrsh3ll/MSBuildAPICaller.git
echo ""
echo "Installing Macro_Pack"
echo ""
sleep 2
git clone https://github.com/sevagas/macro_pack.git
echo ""
echo "Installing Inceptor"
echo ""
sleep 2
git clone https://github.com/klezVirus/inceptor.git
echo ""
echo "Installing Mortar"
echo ""
sleep 2
git clone https://github.com/0xsp-SRD/mortar.git
echo ""
echo "Installing RedTeamCCode"
echo ""
sleep 2
git clone https://github.com/Mr-Un1k0d3r/RedTeamCCode.git
echo ""
sleep 2

###Break For Payload Development###

echo "Cloning Delivery Resources"
echo ""
cd /opt/Delivery/
echo ""
echo "Installing O365 Attack Toolkit"
echo ""
sleep 2
git clone https://github.com/mdsecactivebreach/o365-attack-toolkit.git
echo ""
sleep 2
echo ""
echo "Installing BEEF"
echo ""
sleep 2
git clone https://github.com/beefproject/beef.git
cd beef
bundle install
./install
echo ""

###Break For Delivery###

echo "Cloning Your C2 Resources"
echo ""
cd /opt/Command_And_Control/
echo "Cloning C2 Frameworks"
echo ""
echo "Installing Empire & Starkiller"
echo ""
sleep 2
git clone https://github.com/BC-SECURITY/Empire.git
version=$(lsb_release -sr)
cd Empire/
find ./ -type f -print0 | xargs -0 sed -i "s/20.04/${version}/g"
find ./ -type f -print0 | xargs -0 sed -i "s/18.04/${version}/g"
find ./ -type f -print0 | xargs -0 sed -i "s/21.04/${version}/g"
find ./ -type f -print0 | xargs -0 sed -i "s/21.10/${version}/g"
find ./ -type f -print0 | xargs -0 sed -i "s/16.04/${version}/g"
find ./ -type f -print0 | xargs -0 sed -i "s/22.04/${version}/g"
cd setup/
bash install.sh
cd ../
sudo wget https://github.com/BC-SECURITY/Starkiller/releases/download/v1.8.0/starkiller-1.8.0.AppImage
sudo chmod +x starkiller-1.0.0.AppImage
echo""
sleep 2
cd /opt/Command_And_Control/
echo "Installing PoshC2"
echo ""
git clone https://github.com/nettitude/PoshC2.git
cd PoshC2/
bash Install.sh
cd /opt/Command_And_Control/
echo ""
echo "Installing Merlin C2"
echo ""
sleep 2
git clone https://github.com/Ne0nd0g/merlin.git
cd merlin/
go build
cd /opt/Command_And_Control/
echo ""
echo "Installing Mythic"
echo ""
sleep 2
git clone https://github.com/its-a-feature/Mythic.git
cd Mythic/
./install_docker_ubuntu.sh
echo ""
cd /opt/Command_And_Control/
echo ""
echo "Installing Covenant With Random Profile"
echo ""
echo "Enter A Random Word!"
read Random1
echo ""
echo "Enter A Different Random Word!"
read Random2	
echo ""
echo "Enter A Different Random Word!"
read Random3

custom1=$(echo $custom1 | md5sum | head -c 20)
cd /opt/Command_And_Control/
sudo git clone --recurse-submodules https://github.com/ZeroPointSecurity/Covenant.git

cd /opt/Command_And_Control/Covenant/Covenant/

wget -q https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
sudo apt-get update -y
apt --fix-broken install -y
sudo apt-get install apt-transport-https -y
apt --fix-broken install -y
sudo apt-get update -y
apt --fix-broken install -y
sudo apt-get install dotnet-sdk-3.1 -y
apt --fix-broken install -y

mv ./Data/AssemblyReferences/ ../AssemblyReferences/

mv ./Data/ReferenceSourceLibraries/ ../ReferenceSourceLibraries/

mv ./Data/EmbeddedResources/ ../EmbeddedResources/

mv ./Models/Covenant/ ./Models/${Random1^}/
mv ./Components/CovenantUsers/ ./Components/${Random1^}Users/
mv ./Components/Grunts/ ./Components/${Random2^}s/
mv ./Models/Grunts/ ./Models/${Random2^}s/
mv ./Data/Grunt/GruntBridge/ ./Data/Grunt/${Random2^}Bridge/
mv ./Data/Grunt/GruntHTTP/ ./Data/Grunt/${Random2^}HTTP/
mv ./Data/Grunt/GruntSMB/ ./Data/Grunt/${Random2^}SMB/
mv ./Components/GruntTaskings/ ./Components/${Random2^}Taskings/
mv ./Components/GruntTasks/ ./Components/${Random2^}Tasks/
mv ./Data/Grunt/ ./Data/${Random2^}/
find ./ -type f -print0 | xargs -0 sed -i "s/Grunt/${Random2^}/g"
find ./ -type f -print0 | xargs -0 sed -i "s/GRUNT/${Random2^^}/g"
find ./ -type f -print0 | xargs -0 sed -i "s/grunt/${Random2,,}/g"

#find ./ -type f -print0 | xargs -0 sed -i "s/covenant/${Random1,,}/g"
find ./ -type f -print0 | xargs -0 sed -i "s/Covenant/${Random1^}/g"
find ./ -type f -print0 | xargs -0 sed -i "s/COVENANT/${Random1^^}/g"

find ./ -type f -print0 | xargs -0 sed -i "s/ExecuteStager/ExecLevel/g"
#find ./ -type f -print0 | xargs -0 sed -i "s/REPLACE_PROFILE/REP_PROF/g"
#find ./ -type f -print0 | xargs -0 sed -i "s/REPLACE_PIPE/REP_PIP/g"
#find ./ -type f -print0 | xargs -0 sed -i "s/GUID/ANGID/g"
find ./ -type f -print0 | xargs -0 sed -i "s/SetupAES/Install"${custom1}"AES/g"
find ./ -type f -print0 | xargs -0 sed -i "s/SessionKey/Sess"${custom1}"KEy/g"
find ./ -type f -print0 | xargs -0 sed -i "s/EncryptedChallenge/Enc"${custom1}"ChallEnge/g"

find ./ -type f -print0 | xargs -0 sed -i "s/DecryptedChallenges/Decrypt"${custom1}"ChallEnges/g"
find ./ -type f -print0 | xargs -0 sed -i "s/Stage0Body/First"${custom1}"Body/g"
find ./ -type f -print0 | xargs -0 sed -i "s/Stage0Response/First"${custom1}"Response/g"
find ./ -type f -print0 | xargs -0 sed -i "s/Stage0Bytes/First"${custom1}"Bytes/g"
find ./ -type f -print0 | xargs -0 sed -i "s/Stage1Body/Seccond"${custom1}"Body/g"
find ./ -type f -print0 | xargs -0 sed -i "s/Stage1Response/Seccond"${custom1}"Response/g"
find ./ -type f -print0 | xargs -0 sed -i "s/Stage1Bytes/Seccond"${custom1}"Bytes/g"
find ./ -type f -print0 | xargs -0 sed -i "s/Stage2Body/Third"${custom1}"Body/g"
find ./ -type f -print0 | xargs -0 sed -i "s/Stage2Response/Third"${custom1}"Response/g"
find ./ -type f -print0 | xargs -0 sed -i "s/Stage2Bytes/Third"${custom1}"Bytes/g"
find ./ -type f -print0 | xargs -0 sed -i "s/message64str/messAgE"${custom1}"64str/g"
find ./ -type f -print0 | xargs -0 sed -i "s/messageBytes/messAgE"${custom1}"bytes/g"

find ./ -type f -print0 | xargs -0 sed -i "s/totalReadBytes/ToTal"${custom1}"ReaDBytes/g"
#find ./ -type f -print0 | xargs -0 sed -i "s/inputStream/instream/g"
#find ./ -type f -print0 | xargs -0 sed -i "s/outputStream/outstream/g"
find ./ -type f -print0 | xargs -0 sed -i "s/deflateStream/deFlatE"${custom1}"stream/g"
find ./ -type f -print0 | xargs -0 sed -i "s/memoryStream/memOrYstream/g" #don't change
find ./ -type f -print0 | xargs -0 sed -i "s/compressedBytes/packed"${custom1}"bytes/g"

find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/REPLACE_/REP"${custom1}"_/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/_PROFILE_/_PROF"${custom1}"_/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/_VALIDATE_/_VA"${custom1}"L_/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/GUID/${Random3^^}/g"
find ./ -type f -name "*.razor" -print0 | xargs -0 sed -i "s/GUID/${Random3^^}/g"
find ./ -type f -name "*.json" -print0 | xargs -0 sed -i "s/GUID/${Random3^^}/g"
find ./ -type f -name "*.yaml" -print0 | xargs -0 sed -i "s/GUID/${Random3^^}/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/guid/${Random3,,}/g"
find ./ -type f -name "*.razor" -print0 | xargs -0 sed -i "s/guid/${Random3,,}/g"
find ./ -type f -name "*.json" -print0 | xargs -0 sed -i "s/guid/${Random3,,}/g"
find ./ -type f -name "*.yaml" -print0 | xargs -0 sed -i "s/guid/${Random3,,}/g"
find ./ -type f -print0 | xargs -0 sed -i "s/ProfileHttp/Prof"${custom1}"HTTP/g"
find ./ -type f -print0 | xargs -0 sed -i "s/baseMessenger/bAse"${custom1}"mEsSenger/g"

find ./ -type f -print0 | xargs -0 sed -i "s/PartiallyDecrypted/Part"${custom1}"decrypted/g"
find ./ -type f -print0 | xargs -0 sed -i "s/FullyDecrypted/Fulld"${custom1}"ecrypted/g"
find ./ -type f -print0 | xargs -0 sed -i "s/compressedBytes/packed"${custom1}"bytes/g"

find ./ -type f -print0 | xargs -0 sed -i "s/CookieWebClient/Ottos"${custom1}"WebClient/g"
#find ./ -type f -print0 | xargs -0 sed -i "s/CookieContainer/KekseContains/g"
#find ./ -type f -print0 | xargs -0 sed -i "s/GetWebRequest/DoAnWebReq/g"
find ./ -type f -print0 | xargs -0 sed -i "s/Jitter/JIt"${custom1}"ter/g"
find ./ -type f -print0 | xargs -0 sed -i "s/ConnectAttempts/ConneCT"${custom1}"AttEmpts/g"
find ./ -type f -print0 | xargs -0 sed -i "s/RegisterBody/Reg"${custom1}"Body/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/messenger/meSsenGer"${custom1}"/g"
find ./ -type f -print0 | xargs -0 sed -i "s/Hello World/"${custom1}"/g"
find ./ -type f -print0 | xargs -0 sed -i "s/ValidateCert/Val"${custom1}"CerT/g"
find ./ -type f -print0 | xargs -0 sed -i "s/UseCertPinning/UsCert"${custom1}"Pin/g"
find ./ -type f -print0 | xargs -0 sed -i "s/EncryptedMessage/Enc"${custom1}"Msg/g"
find ./ -type f -print0 | xargs -0 sed -i "s/cookieWebClient/"${custom1}"WebClient/g" #ottos
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/aes/crypt"${custom1}"var/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/aes2/crypt"${custom1}"var2/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/array5/ar"${custom1}"r5/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/array6/ar"${custom1}"r6/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/array4/ar"${custom1}"r4/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/array7/ar"${custom1}"r7/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/array1/ar"${custom1}"r1/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/array2/ar"${custom1}"r2/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/array3/ar"${custom1}"r3/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/list1/l"${custom1}"i1/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/list2/l"${custom1}"i2/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/list3/l"${custom1}"i3/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/list4/l"${custom1}"i4/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/list5/l"${custom1}"i5/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/group0/gr"${custom1}"p0/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/group1/gr"${custom1}"p1/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/group2/gr"${custom1}"p2/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/group3/gr"${custom1}"p3/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/group4/gr"${custom1}"p4/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/group5/gr"${custom1}"p5/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/group6/gr"${custom1}"p6/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/group7/gr"${custom1}"p7/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/group8/gr"${custom1}"p8/g"

find ./ -type f -name "*Grunt*" | while read FILE ; do
	newfile="$(echo ${FILE} |sed -e "s/Grunt/${Random2^}/g")";
	mv "${FILE}" "${newfile}";
done
find ./ -type f -name "*GRUNT*" | while read FILE ; do
	newfile="$(echo ${FILE} |sed -e "s/GRUNT/${Random2^^}/g")";
	mv "${FILE}" "${newfile}";
done

find ./ -type f -name "*grunt*" | while read FILE ; do
	newfile="$(echo ${FILE} |sed -e "s/grunt/${Random2,,}/g")";
	mv "${FILE}" "${newfile}";
done

find ./ -type f -name "*Covenant*" | while read FILE ; do
	newfile="$(echo ${FILE} |sed -e "s/Covenant/${Random1^}/g")";
	mv "${FILE}" "${newfile}";
done

find ./ -type f -name "*COVENANT*" | while read FILE ; do
	newfile="$(echo ${FILE} |sed -e "s/COVENANT/${Random2^^}/g")";
	mv "${FILE}" "${newfile}";
done

#find ./ -type f -name "*covenant*" | while read FILE ; do
#	newfile="$(echo ${FILE} |sed -e "s/covenant/ottocommand/g")";
#	mv "${FILE}" "${newfile}";
#done

mv ../AssemblyReferences/ ./Data/ 

mv ../ReferenceSourceLibraries/ ./Data/ 

mv ../EmbeddedResources/ ./Data/ 

dotnet build
echo ""
cd /opt/Command_And_Control/
echo "Installing Shad0w"
echo ""
sleep 2
git clone https://github.com/bats3c/shad0w.git
cd shad0w/
bash install.sh
echo ""
cd /opt/Command_And_Control/
echo "Installing Sliver"
echo ""
sleep 2
git clone https://github.com/BishopFox/sliver.git
cd sliver/
python3 build.py
cd /opt/Command_And_Control
echo ""
echo "Installing SilentTrinity"
echo ""
sleep 2
git clone https://github.com/byt3bl33d3r/SILENTTRINITY.git
cd SILENTTRINITY/
pip3 install -r requirements.txt
cd /opt/Command_And_Control/
echo ""
echo "Installing Pupy C2"
echo ""
sleep 2
git clone https://github.com/n1nj4sec/pupy.git
echo ""
echo "Installing Metasploit"
sleep 2
echo ""
apt install postgresql -y
systemctl start postgresql 
systemctl enable postgresql
apt install curl -y
apt --fix-broken install -y
cd /opt/Command_And_Control/
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod +x msfinstall
./msfinstall
apt --fix-broken install -y
echo ""

###Break For C2 Frameworks###

echo "Cloning Staging Resources"
echo ""
cd /opt/Staging/
echo""
echo "Installing PwnDrop"
git clone https://github.com/kgretzky/pwndrop.git
cd pwndrop/
go build
cd /opt/Staging
echo ""
echo "Installing C2 Concealer"
echo ""
sleep 2
git clone https://github.com/FortyNorthSecurity/C2concealer.git
cd C2concealer/
bash install.sh
cd /opt/Staging/
echo ""
echo "Installing FindFrontableDomains"
echo ""
sleep 2
git clone https://github.com/rvrsh3ll/FindFrontableDomains.git
cd FindFrontableDomains/
bash install.sh
echo ""
echo "Installing DomainHunter"
echo ""
cd /opt/Staging/
sleep 2
git clone https://github.com/threatexpress/domainhunter.git
cd domainhunter/
pip3 install -r requirements.txt
echo ""
cd /opt/Staging/
echo "Installing RedWarden"
echo ""
sleep 2
git clone https://github.com/mgeeky/RedWarden.git
cd RedWarden/
pip3 install -r requirements.txt
cd /opt/Staging/
echo ""
echo "Installing AzureC2Relay"
echo ""
sleep 2
git clone https://github.com/Flangvik/AzureC2Relay.git
echo ""
echo "Installing C3"
echo ""
sleep 2
cd /opt/Windows_OS
git clone https://github.com/FSecureLABS/C3.git
echo ""
cd /opt/Staging/
echo "Installing Chameleon"
echo ""
sleep 2
git clone https://github.com/mdsecactivebreach/Chameleon.git
cd Chameleon/
pip3 install -r requirements.txt
cd /opt/Staging/
echo ""
echo "Installing Redirect Rules"
echo ""
sleep 2
git clone https://github.com/0xZDH/redirect.rules.git 
cd redirect.rules/
bash setup.sh
echo ""
echo "Installing Log Aggregation Resources"
echo ""
sleep 2
cd /opt/Log_Aggregation
echo ""
echo "Installing RedELK"
echo ""
sleep 2
git clone https://github.com/outflanknl/RedELK.git
echo ""
echo "Installing RedTeamSIEM"
echo ""
sleep 2
git clone https://github.com/SecurityRiskAdvisors/RedTeamSIEM.git
echo ""
echo "Installing Situational Awareness Resources"
echo ""
sleep 2
cd /opt/Windows_OS
mkdir Situational_Awareness
cd Situational_Awareness/
echo ""
echo "Installing AggressiveProxy"
echo ""
sleep 2
git clone https://github.com/EncodeGroup/AggressiveProxy.git
echo ""
echo "Installing Gopher"
echo ""
sleep 2
git clone https://github.com/EncodeGroup/Gopher.git
echo ""
echo "Installing SharpEDRChecker"
echo ""
sleep 2
git clone https://github.com/PwnDexter/SharpEDRChecker.git
echo ""
echo "Installing CS-Situational-Awareness-BOF"
echo ""
sleep 2
git clone https://github.com/trustedsec/CS-Situational-Awareness-BOF.git
echo ""
echo "Installing Seatbelt"
echo ""
sleep 2
git clone https://github.com/GhostPack/Seatbelt.git
echo ""
echo "Installing SauronEye"
echo ""
sleep 2
git clone https://github.com/vivami/SauronEye.git
echo ""
echo "Installing SharpShares"
echo ""
sleep 2
git clone https://github.com/mitchmoser/SharpShares.git
echo ""
echo "Installing SharpAppLocker"
echo ""
sleep2
git clone https://github.com/Flangvik/SharpAppLocker/.git
echo ""
echo "Installing SharpPrinter"
echo ""
sleep 2
git clone https://github.com/rvrsh3ll/SharpPrinter.git
echo ""
echo "Installing Standin"
echo ""
git clone https://github.com/FuzzySecurity/StandIn.git
echo ""
echo "Installing Recon-AD"
echo ""
sleep 2
git clone https://github.com/outflanknl/Recon-AD.git
echo ""
echo "Cloning BloodHound For Windows"
echo ""
sleep 2
git clone https://github.com/BloodHoundAD/BloodHound.git
echo ""
echo "Installing PSPKIAudit"
echo ""
sleep 2
git clone https://github.com/GhostPack/PSPKIAudit.git
echo ""
echo "Installing SharpView"
echo ""
sleep 2
git clone https://github.com/tevora-threat/SharpView.git
echo ""
echo "Installing Rubeus"
echo ""
sleep 2
git clone https://github.com/GhostPack/Rubeus.git
echo ""
echo "Installing Grouper"
echo ""
sleep 2
git clone https://github.com/l0ss/Grouper.git
echo ""
echo "Installing ImproHound"
echo ""
sleep 2
git clone https://github.com/improsec/ImproHound.git
echo ""
echo "Installing ADRecon"
echo ""
sleep 2
git clone https://github.com/adrecon/ADRecon.git
echo ""
echo "Installing ADCSPwn"
echo ""
sleep2
git clone https://github.com/bats3c/ADCSPwn.git
echo ""
echo "Cloning Credential Dumping Resource"
echo ""
sleep 2
cd /opt/Windows_OS
mkdir Credential_Dumping
cd Credential_Dumping/
echo ""
echo "Cloning Mimikatz"
echo ""
sleep2
git clone https://github.com/gentilkiwi/mimikatz.git
echo ""
echo "Cloning Dumpert"
echo ""
sleep 2
git clone https://github.com/outflanknl/Dumpert.git
echo ""
echo "Cloning SharpLAPS"
echo ""
sleep 2
git clone https://github.com/swisskyrepo/SharpLAPS.git
echo ""
echo "Cloning SharpDPAPI"
echo ""
sleep 2
git clone https://github.com/GhostPack/SharpDPAPI.git
echo ""
echo "Cloning KeeThief"
echo ""
sleep 2
git clone https://github.com/GhostPack/KeeThief.git
echo ""
echo "Cloning SafetyKatz"
echo ""
sleep 2
git clone https://github.com/GhostPack/SafetyKatz.git
echo ""
echo "Cloning Forkatz"
echo ""
sleep 2
git clone https://github.com/Barbarisch/forkatz.git
echo ""
echo "Cloning PPLKiller"
echo ""
sleep 2
git clone https://github.com/RedCursorSecurityConsulting/PPLKiller.git
echo ""
echo "Cloning LaZagne"
echo ""
sleep 2
git clone https://github.com/AlessandroZ/LaZagne.git
echo ""
echo "Cloning AndrewSpecial"
echo ""
sleep 2
git clone https://github.com/hoangprod/AndrewSpecial.git
echo ""
echo "Cloning Net-GPPassword"
echo ""
sleep 2
git clone https://github.com/outflanknl/Net-GPPPassword.git
echo ""
echo "Cloning SharpChromium"
echo ""
sleep 2
git clone https://github.com/djhohnstein/SharpChromium.git
echo ""
echo "Cloning Chlonium"
echo ""
sleep 2
git clone https://github.com/rxwx/chlonium.git
echo ""
echo "Cloning SharpCloud"
echo ""
sleep 2
git clone https://github.com/chrismaddalena/SharpCloud.git
echo ""
echo "Cloning PypyKatz"
echo ""
sleep 2
git clone https://github.com/skelsec/pypykatz.git
echo ""
echo "Cloning NanoDump"
echo ""
sleep 2
git clone https://github.com/helpsystems/nanodump.git
echo ""
sleep 2
echo "Installing Privilege Escalation Resources"
echo ""
cd /opt/Windows_OS/
mkdir Privilege_Escalation
cd Privilege_Escalation/
echo ""
echo "Installing ElevateKit"
echo ""
sleep 2
git clone https://github.com/rsmudge/ElevateKit.git
echo ""
echo "Cloning Watson"
cd /opt/Windows_OS/
echo ""
sleep 2
git clone https://github.com/rasta-mouse/Watson.git
echo ""
echo "Cloning SharpUp"
echo ""
sleep 2
git clone https://github.com/GhostPack/SharpUp.git
echo ""
echo "Cloning dazzleUp"
echo ""
sleep 2
git clone https://github.com/hlldz/dazzleUP.git
echo ""
echo "Cloning PEASS-ng"
echo ""
sleep 2
git clone https://github.com/carlospolop/PEASS-ng.git
echo ""
echo "Cloning SweetPotato"
echo ""
sleep 2
git clone https://github.com/CCob/SweetPotato.git
echo ""
echo "Cloning MultiPotato"
echo ""
git clone https://github.com/S3cur3Th1sSh1t/MultiPotato.git
echo ""
echo "Cloning Defense Evasion Resources -- This is all Windows Based"
echo ""
sleep 2
cd /opt/Windows_OS/
mkdir Defense_Evasion
cd Defense_Evasion/
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
echo ""
echo "Cloning Social Engineering Resources"
echo ""
sleep 2
cd /opt/Social_Engineering
echo ""
echo "Installing Social Engineering Toolkit"
echo ""
sleep 2
git clone https://github.com/trustedsec/social-engineer-toolkit.git
cd social-engineering-toolkit/
pip3 install -r requirements.txt
python3 setup.py install
cd /opt/Social_Engineering/
echo ""
echo "Installing Social Engineering Payloads"
echo ""
sleep 2
git clone https://github.com/bhdresh/SocialEngineeringPayloads.git
echo ""
echo "Cloning Phishing Resources"
echo ""
sleep 2
cd /opt/Phishing/
echo ""
echo "Installing Phishery"
echo ""
sleep 2
mkdir phishery
cd phishery
wget https://github.com/ryhanson/phishery/releases/download/v1.0.2/phishery1.0.2linux-amd64.tar.gz
tar -xzvf phishery*.tar.gz
cp phishery /usr/local/bin
cd /opt/Phishing/
echo ""
echo "Installing EvilginX2"
echo ""
sleep 2
git clone https://github.com/kgretzky/evilginx2.git
cd evilginx2/
make
sudo make install
cd /opt/Phishing/
echo ""
echo "Installing PwnAuth"
echo ""
sleep 2
git clone https://github.com/fireeye/PwnAuth.git
cd PwnAuth/
bash setup.sh
cd /opt/Phishing/
echo ""
echo "Installig Modlishka"
echo ""
sleep 2
git clone https://github.com/drk1wi/Modlishka.git
cd Modlishka/
make 
go build
cd /opt/Phishing/
echo ""
echo "Installing King-Phisher"
echo ""
sleep 2
git clone https://github.com/securestate/king-phisher.git
echo ""
echo "Installing FiercePhish"
echo ""
sleep 2
git clone https://github.com/Raikia/FiercePhish.git
cd FiercePhish/
bash install.sh
echo ""
echo "Installing ReelPhish"
echo ""
sleep 2
git clone https://github.com/fireeye/ReelPhish.git
cd ReelPhish/
pip3 install -r requirements.txt
cd /opt/Phishing/
echo ""
echo "Installing GoPhish"
echo ""
sleep 2
git clone https://github.com/gophish/gophish.git
cd gophish/
go build
echo ""
cd /opt/Phishing/
echo "Installing CredSniper"
echo ""
sleep 2
git clone https://github.com/ustayready/CredSniper.git
cd CredSniper/
read -p "Just Hit Enter Until All Dependencies Are Installed"
cd /opt/Phishing/
echo ""
echo "Cloning Phishing Pretexts"
echo ""
sleep 2
git clone https://github.com/L4bF0x/PhishingPretexts.git
echo ""
echo "Cloning Persistence Resources"
cd /opt/Windows_OS
mkdir Persistence
cd Persistence/
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
echo ""
echo "Cloning Lateral Movement Resources"
echo ""
echo ""
cd /opt/Lateral_Movement/
echo ""
echo "Installing Responder"
echo ""
sleep 2
git clone https://github.com/lgandx/Responder.git
echo ""
echo "Installing MITM6"
echo ""
sleep 2
git clone https://github.com/dirkjanm/mitm6.git
cd mitm6/
pip3 install -r requirements.txt
python3 setup.py install
cd /opt/Lateral_Movement/
echo ""
echo "Installing Impacket"
echo ""
sleep 2
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket/
python3 setup.py install
echo ""
sleep 2
cd /opt/Lateral_Movement/
echo "Cloning CrackMapExec"
git clone https://github.com/byt3bl33d3r/CrackMapExec.git
cd CrackMapExec/
echo "Cloning Windows Lateral Movement Resources"
echo ""
sleep 2
cd /opt/Windows_OS/
mkdir Lateral_Movement
cd Lateral_Movement/
git clone https://github.com/RiccardoAncarani/LiquidSnake.git
git clone https://github.com/NetSPI/PowerUpSQL.git
git clone https://github.com/0xthirteen/SharpRDP.git
git clone https://github.com/0xthirteen/MoveKit.git
git clone https://github.com/juliourena/SharpNoPSExec.git
git clone https://github.com/mdsecactivebreach/Farmer.git
git clone https://github.com/FortyNorthSecurity/CIMplant.git
git clone https://github.com/Mr-Un1k0d3r/PowerLessShell.git
git clone https://github.com/FSecureLABS/SharpGPOAbuse.git
git clone https://github.com/ropnop/kerbrute.git 
git clone https://github.com/blackarrowsec/mssqlproxy.git
git clone https://github.com/Kevin-Robertson/Invoke-TheHash.git
git clone https://github.com/Kevin-Robertson/InveighZero.git
git clone https://github.com/jnqpblc/SharpSpray/git
git clone https://github.com/pkb1s/SharpAllowedToAct.git
git clone https://github.com/bohops/SharpRDPHijack.git
git clone https://github.com/klezVirus/CheeseTools.git
git clone https://github.com/PowerShellMafia/PowerSploit.git
git clone https://github.com/DanMcInerney/icebreaker.git
git clone https://github.com/JavelinNetworks/HoneypotBuster.git
echo ""
echo "Cloning Exfiltration Resources"
echo ""
sleep 2
cd /opt/Windows_OS
mkdir Exfiltration
cd Exfiltration/
echo ""
sleep 2
git clone https://github.com/Flangvik/SharpExfiltrate.git
git clone https://github.com/Arno0x/DNSExfiltrator.git
git clone https://github.com/FortyNorthSecurity/Egress-Assess.git
echo ""
echo "Cloning Cloud Resources"
echo ""
sleep 2
cd /opt/Cloud
echo ""
mkdir AWS
cd AWS/
echo "Installing AWS Resources"
echo ""
sleep 2
echo ""
echo "Installing Pacu"
echo ""
sleep 2
git clone https://github.com/RhinoSecurityLabs/pacu.git
cd pacu/
bash install.sh
echo ""
cd /opt/Cloud/AWS/
echo "Installing CloudMapper"
echo ""
sleep 2
git clone https://github.com/duo-labs/cloudmapper.git
pip3 install -r requirements.txt
echo ""
echo "Installing Enumerate-IAM"
echo ""
sleep 2
cd /opt/Cloud/AWS/
git clone https://github.com/andresriancho/enumerate-iam.git
cd enumerate-iam/
pip3 install -r requirements.txt
echo ""
cd /opt/Cloud/AWS/
echo "Installing AWSBucketDump"
echo ""
sleep 2
git clone https://github.com/jordanpotti/AWSBucketDump.git
cd AWSBucketDump/
pip3 install -r requirements.txt
cd /opt/Cloud/
mkdir Azure
cd Azure
echo "Installing Azure Resources"
echo ""
echo "Installing ADConnectDump"
echo ""
sleep 2
git clone https://github.com/fox-it/adconnectdump.git
echo ""
cd /opt/Cloud/Azure/
echo ""
echo "Installing Stormspotter"
echo ""
sleep 2
git clone https://github.com/Azure/Stormspotter.git
cd /opt/Cloud/Azure/
echo ""
echo "Installing ROADtools"
echo ""
sleep 2
git clone https://github.com/dirkjanm/ROADtools.git
cd ROADtools/
pip install -e roadlib/
pip install -e roadrecon/
cd roadrecon/frontend/
npm install
npm audit fix
echo ""
echo "Installing MicroBurst"
echo ""
sleep 2
cd /opt/Cloud/Azure/
git clone https://github.com/NetSPI/MicroBurst.git
echo ""
echo "Installing AADInternals"
echo ""
sleep 2
cd /opt/Windows_OS/
mkdir Cloud
cd Cloud
mkdir Azure
cd Azure
git clone https://github.com/Gerenios/AADInternals.git 
echo ""
echo "Cloning Hak5 Implant Resources"
echo ""
cd /opt/Hak5_Implants
echo ""
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
echo ""
echo "Cloning Wireless Resources"
echo ""
cd /opt/Wireless
echo ""
echo "Installing BeRateAP"
echo ""
sleep 2
git clone https://github.com/sensepost/berate_ap
echo ""
cd /opt/Wireless
echo "Installing EvilTwin Capitive Portal"
echo ""
sleep 2
git clone https://github.com/athanstan/EvilTwin_AP_CaptivePortal.git
echo ""
cd /opt/Wireless
echo "Installing Fluxion"
echo ""
sleep 2
git clone https://www.github.com/FluxionNetwork/fluxion.git
echo ""
echo "Installing Bettercap"
echo ""
sleep 2
git clone https://github.com/bettercap/bettercap
cd bettercap/
bash build.sh
echo ""
echo "Installing Airgeddon"
echo ""
sleep 2
git clone https://github.com/v1s1t0r1sh3r3/airgeddon.git
echo ""
cd /opt/Wireless/
mkdir Wireless_Drivers
cd Wireless_Drivers/
apt install dkms -y
git clone https://github.com/aircrack-ng/rtl8812au
cd rtl8812au/
make && make install
cd /opt/Virtual_Machines
echo "Installing VirtualBox"
echo ""
sleep 3
apt-get update -y && apt-get upgrade -y
apt --fix-broken install -y
wget https://download.virtualbox.org/virtualbox/6.1.34/virtualbox-6.1_6.1.34-150636.1~Ubuntu~eoan_amd64.deb
dpkg --install virtualbox-6.1_6.1.34-150636.1~Ubuntu~eoan_amd64.deb
echo""
echo "Downloading Kali VM"
echo ""
wget https://kali.download/virtual-images/kali-2022.1/kali-linux-2022.1-virtualbox-amd64.ova
echo ""
echo "Downloading Windows Ops Box"
echo ""
sleep 2
wget https://az792536.vo.msecnd.net/vms/VMBuild_20190311/VirtualBox/MSEdge/MSEdge.Win10.VirtualBox.zip
echo ""
sleep 2 
echo ""
read -p "Press Enter To Reboot Your New C2 Box"
reboot now
