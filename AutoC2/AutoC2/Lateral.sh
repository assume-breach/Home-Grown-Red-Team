echo ""
echo "Cloning Lateral Movement Resources"
echo ""
mkdir /opt/Windows_OS >/dev/null 2>&1
mkdir /opt/Lateral_Movement >/dev/null 2>&1
cd /opt/Lateral_Movement/
apt install ettercap-graphical -y
echo ""
echo "Installing LDAP Tools"
echo ""
apt install ldap-utils -y
echo ""
echo "Installing Kerbrute"
echo ""
git clone https://github.com/ropnop/kerbrute.git
echo ""
echo "Installing Petitpotam"
sleep 2
git clone https://github.com/topotam/PetitPotam.git
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
mkdir Lateral_Movement >/dev/null 2>&1
cd Lateral_Movement/
git clone https://github.com/nettitude/SharpWSUS
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
