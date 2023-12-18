apt-get update -y && apt-get upgrade -y 
apt update -y && apt upgrade -y
apt autoremove -y
echo ""
sleep 2
echo "Installing System Dependencies"
echo ""
sleep 2
apt --fix-broken install
apt install git -y
apt --fix-broken install
apt install net-tools -y 
apt install gparted -y
apt install php-curl -y 
apt install php-xml -y
apt install docker -y
apt install docker.io -y 
apt install ruby-bundler -y 
apt install golang -y
apt install python-pip -y 
apt install python3 -y 
apt install make -y 
apt install snap -y 
apt install fuse -y
apt install ruby-bundler -y 
apt install pipx -y 
apt install chromium-browser -y 
apt install dnsmasq -y 
apt install hostapd -y 
apt install openssl -y 
apt install open-vm-tools-desktop -y
apt install build-essential -y
apt install libpcap-dev -y
apt install terminator -y
apt install macchanger -y
apt install dhcpd -y
apt install lighttpd -y
apt install mdk4 -y
apt install dsniff -y
apt install mdk3 -y
apt install php-cgi -y
ap install xterm -y
apt install tshark -y
apt --fix-broken install

echo "Cloning Your C2 Resources"
echo ""
mkdir /opt/Command_And_Control >/dev/null 2>&1
cd /opt/Command_And_Control/
echo "Cloning C2 Frameworks"
echo ""
echo "Installing Empire & Starkiller"
echo ""
sleep 2
git clone https://github.com/BC-SECURITY/Empire.git
version=$(lsb_release -sr)
cd Empire/
pip install poetry -y
wget https://github.com/PowerShell/PowerShell/releases/download/v7.2.2/powershell-lts_7.2.2-1.deb_amd64.deb
dpkg -i powershell-lts_7.2.2-1.deb_amd64.deb
find ./ -type f -print0 | xargs -0 sed -i "s/20.04/${version}/g"
find ./ -type f -print0 | xargs -0 sed -i "s/18.04/${version}/g"
find ./ -type f -print0 | xargs -0 sed -i "s/21.04/${version}/g"
find ./ -type f -print0 | xargs -0 sed -i "s/21.10/${version}/g"
find ./ -type f -print0 | xargs -0 sed -i "s/16.04/${version}/g"
find ./ -type f -print0 | xargs -0 sed -i "s/22.04/${version}/g"
find ./ -type f -print0 | xargs -0 sed -i "s/22.10/${version}/g"

cd setup/
bash install.sh
cd ../
sudo wget https://github.com/BC-SECURITY/Starkiller/releases/download/v1.8.0/starkiller-1.8.0.AppImage
sudo chmod +x starkiller-1.8.0.AppImage
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
echo "Welcome To Covenant Randomizer!"
sleep 2
echo ""
echo "Covenant Randomizer now uses Docker. Refer to the github for the docker command to start Covenant"
echo ""
sleep 3
echo "Enter A Random Word!"
read Random1
echo ""
echo "Enter A Different Random Word!"
read Random2	
echo ""
echo "Enter A Different Random Word!"
read Random3
apt --fix-broken install

apt install -y docker
apt --fix-broken install

custom1=$(echo $custom1 | md5sum | head -c 20)

sudo git clone --recurse-submodules https://github.com/ZeroPointSecurity/Covenant.git /opt/Covenant

cd /opt/Covenant/Covenant/

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

docker build -t covenant .

echo ""
cd /opt/Command_And_Control/
echo ""
echo "Installing Shad0w"
echo ""
sleep 2
git clone https://github.com/bats3c/shad0w.git
cd shad0w/
bash install.sh
echo ""
cd /opt/Command_And_Control/
echo "Installing Havoc C2"
echo ""
git clone https://github.com/HavocFramework/Havoc.git
echo ""
sudo apt install -y git build-essential apt-utils cmake libfontconfig1 libglu1-mesa-dev libgtest-dev libspdlog-dev libboost-all-dev libncurses5-dev libgdbm-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev libbz2-dev mesa-common-dev qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools libqt5websockets5 libqt5websockets5-dev qtdeclarative5-dev golang-go qtbase5-dev libqt5websockets5-dev python3-dev libboost-all-dev mingw-w64 nasm -y
sleep 2
echo ""
echo "Installing Sliver"
echo ""
sleep 2
git clone https://github.com/BishopFox/sliver.git
cd sliver/
python3 build.py
cd /opt/Command_And_Control
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
mv /opt/Covenant /opt/Command_And_Control
