echo ""
echo "Cloning Wireless Resources"
echo ""
mkdir /opt/Wireless >/dev/null 2>&1
cd /opt/Wireless/

apt install wifite -y
apt install aircrack-ng -y
echo ""
echo "Installing BeRateAP"
echo ""
sleep 2
git clone https://github.com/sensepost/berate_ap
echo ""
cd /opt/Wireless/
echo "Installing EvilTwin Capitive Portal"
echo ""
sleep 2
git clone https://github.com/athanstan/EvilTwin_AP_CaptivePortal.git
echo ""
cd /opt/Wireless/
echo "Installing Fluxion"
echo ""
sleep 2
git clone https://www.github.com/FluxionNetwork/fluxion.git
echo ""
echo "Installing Bettercap"
echo ""
sleep 2
git clone https://github.com/bettercap/bettercap
cd bettercap/
bash build.sh
echo ""
echo "Installing Airgeddon"
echo ""
sleep 2
git clone https://github.com/v1s1t0r1sh3r3/airgeddon.git
echo ""
cd /opt/Wireless/
echo "Installing HCXTools"
echo ""
sleep 2
git clone https://github.com/ZerBea/hcxtools
cd hcxtools/
make && make install
echo "Installing HCX Dump Tool"
cd /opt/Wireless/
git clone https://github.com/ZerBea/hcxdumptool
cd hcxdumptool/
make && make install
cd /opt/Wireless/
echo "Installing Bully"
echo ""
sleep 2
git clone https://github.com/aanarchyy/bully
cd bully/src
make && make install
cd /opt/Wireless/
echo "Installing EapHammer"
echo ""
sleep 2
git clone https://github.com/s0lst1c3/eaphammer.git
cd eaphammer/
./kali-setup
cd /opt/Wireless
mkdir Wireless_Drivers  >/dev/null 2>&1
cd Wireless_Drivers/
apt install dkms -y
git clone https://github.com/aircrack-ng/rtl8812au
cd rtl8812au/
make && make install
