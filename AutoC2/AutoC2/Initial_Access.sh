echo""
echo "Installing Initial Access Tools"
echo ""
sleep 2
mkdir /opt/Initial_Access >/dev/null 2>&1
cd /opt/Initial_Access/
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
echo ""
echo "Installing O365 Attack Toolkit"
echo ""
sleep 2
git clone https://github.com/mdsecactivebreach/o365-attack-toolkit.git
echo ""
