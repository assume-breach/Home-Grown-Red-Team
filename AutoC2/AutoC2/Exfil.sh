echo ""
echo "Cloning Exfiltration Resources"
echo ""
sleep 2
mkdir /opt/Windows_OS >/dev/null 2>&1
cd /opt/Windows_OS/
mkdir Exfiltration >/dev/null 2>&1
cd Exfiltration/
echo ""
sleep 2
git clone https://github.com/Flangvik/SharpExfiltrate.git
git clone https://github.com/Arno0x/DNSExfiltrator.git
git clone https://github.com/FortyNorthSecurity/Egress-Assess.git
