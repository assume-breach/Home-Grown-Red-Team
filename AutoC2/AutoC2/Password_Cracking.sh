echo ""
echo "Installing Password Cracking Tools"
echo ""
mkdir /opt/Password_Cracking/>/dev/null 2>&1
apt install john -y
apt install hashcat -y
apt install crunch -y
apt install cewl -y
apt install hydra -y
apt install ncrack -y
apt install medusa -y



