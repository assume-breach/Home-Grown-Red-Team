mkdir /opt/Virtual_Machines >/dev/null 2>&1
cd /opt/Virtual_Machines
echo "Installing VirtualBox"
echo ""
sleep 3
apt-get update -y && apt-get upgrade -y
apt --fix-broken install -y
wget https://download.virtualbox.org/virtualbox/6.1.38/Oracle_VM_VirtualBox_Extension_Pack-6.1.38.vbox-extpack
wget https://download.virtualbox.org/virtualbox/6.1.38/virtualbox-6.1_6.1.38-153438~Ubuntu~jammy_amd64.deb
apt --fix-broken install -y
dpkg --install virtualbox-6.1_6.1.34-150636.1~Ubuntu~eoan_amd64.deb
echo""
echo "Downloading Kali VM"
echo ""
wget https://kali.download/virtual-images/kali-2022.3/kali-linux-2022.3-virtualbox-amd64.7z
echo ""
echo "Downloading Windows ISO (Build The Box Yourself And Activate With MassGrave Activation"
echo ""
sleep 2
wget https://pixeldrain.com/api/file/yKpSj3P7?download
echo ""
echo "Cloning MassGrave's Windows Activation Scripts'"
git clone https://github.com/massgravel/Microsoft-Activation-Scripts.git
sleep 2 
echo ""
apt --fix-broken install -y
