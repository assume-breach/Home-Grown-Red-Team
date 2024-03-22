mkdir /opt/Virtual_Machines >/dev/null 2>&1
cd /opt/Virtual_Machines
echo "Installing VirtualBox"
echo ""
sleep 3
apt-get update -y && apt-get upgrade -y
apt --fix-broken install -y
wget https://download.virtualbox.org/virtualbox/7.0.14/Oracle_VM_VirtualBox_Extension_Pack-7.0.14.vbox-extpack
wget https://download.virtualbox.org/virtualbox/7.0.14/virtualbox-7.0_7.0.14-161095~Ubuntu~jammy_amd64.deb
apt --fix-broken install -y
dpkg --install virtualbox-7.0_7.0.14-161095~Ubuntu~jammy_amd64.deb
echo""
echo "Downloading Kali VM"
echo ""
wget https://cdimage.kali.org/kali-2024.1/kali-linux-2024.1-virtualbox-amd64.7z
echo ""
echo "Downloading Windows ISO (Build The Box Yourself And Activate With MassGrave Activation"
echo ""
sleep 2
wget https://drive.massgrave.dev/en-us_windows_11_consumer_editions_version_23h2_updated_march_2024_x64_dvd_bcbf6ac6.iso
echo ""
echo "Cloning MassGrave's Windows Activation Scripts'"
git clone https://github.com/massgravel/Microsoft-Activation-Scripts.git
sleep 2 
echo ""
apt --fix-broken install -y
