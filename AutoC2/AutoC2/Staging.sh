echo "Cloning Staging Resources"
echo ""
mkdir /opt/Staging >/dev/null 2>&1
mkdir /opt/Windows_OS >/dev/null 2>&1
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
