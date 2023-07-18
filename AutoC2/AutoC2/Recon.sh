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
cd /opt
mkdir Recon >/dev/null 2>&1
mkdir Windows_OS >/dev/null 2>&1
echo""
echo "Installing Recon Resources"
echo""
sleep 2
cd /opt/Recon/
echo""
echo "Installing Nmap, Dirb, GoBuster & wfuzz"
echo ""
apt install nmap -y
apt install dirb -y
apt install wfuzz -y
apt install gobuster -y
echo "Installing Nikto & WPScan"
echo ""
apt install nikto -y
apt install wpscan -y 
echo ""
echo "Installing Recon-NG"
apt install recon-ng -y
echo ""
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
cd /opt/Windows_OS/
cd Recon/
echo "Installing MFA Sweep"
echo ""
sleep 2
git clone https://github.com/dafthack/MFASweep 
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
