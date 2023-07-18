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
echo "Cloning Cloud Resources"
echo ""
sleep 2
mkdir /opt/Windows_OS >/dev/null 2>&1
mkdir /opt/Cloud >/dev/null 2>&1
cd /opt/Cloud
echo ""
mkdir AWS >/dev/null 2>&1
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
mkdir Azure >/dev/null 2>&1
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
mkdir Cloud >/dev/null 2>&1
cd Cloud
mkdir Azure >/dev/null 2>&1
cd Azure
git clone https://github.com/Gerenios/AADInternals.git 
