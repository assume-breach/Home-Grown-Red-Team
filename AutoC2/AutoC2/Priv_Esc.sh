echo "Installing Privilege Escalation Resources"
echo ""
mkdir /opt/Windows_OS >/dev/null 2>&1
cd /opt/Windows_OS/
mkdir Privilege_Escalation >/dev/null 2>&1
cd Privilege_Escalation/
echo ""
echo "Installing ElevateKit"
echo ""
sleep 2
git clone https://github.com/rsmudge/ElevateKit.git
echo ""
echo "Cloning Watson"
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
sleep 2
echo "Cloning SharpEFSPotato"
echo ""
git clone https://github.com/bugch3ck/SharpEfsPotato.git
echo ""
