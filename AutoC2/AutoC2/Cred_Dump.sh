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
echo ""
echo "Cloning Credential Dumping Resource"
echo ""
sleep 2
mkdir /opt/Windows_OS >/dev/null 2>&1
cd /opt/Windows_OS
mkdir Credential_Dumping >/dev/null 2>&1
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
