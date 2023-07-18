echo "Creating Powershell Resources"
mkdir /opt/Powershell >/dev/null 2>&1
echo ""
echo "Cloning PowerSploit"
echo ""
cd /opt/Powershell
git clone https://github.com/PowerShellMafia/PowerSploit.git
echo""
echo "Cloning PowerSCCM"
echo ""
git clone https://github.com/PowerShellMafia/PowerSCCM.git
