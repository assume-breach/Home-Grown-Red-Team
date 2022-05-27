#!/bin/sh -e

if [ "$(id -u)" != "0" ]; then
   echo "Run as Root" 1>&2
   exit 1
fi

sudo apt-get update -y && apt-get upgrade -y

apt install npm -y

git clone --depth 1 --recursive https://github.com/gildas-lormeau/SingleFile.git

chown -R pi:pi SingleFile/

cd SingleFile

npm install

cd cli

chmod +x single-file

cd ../../

sudo apt install tmux apache2 iptables php dnsmasq apache2 dnsmasq-base python hostapd mdk4 macchanger pkg-config libnl-3-dev libnl-genl-3-dev libpcap-dev
wifite cewl hashcat -y
https://github.com/praetorian-inc/Hob0Rules.git
git clone https://github.com/adamff24/PwrDeauther.git

cp -f dnsmasq.conf /etc/

cp -Rf html /var/www/

chown -R www-data:www-data /var/www/html

chown root:www-data /var/www/html/.htaccess

chmod 777 /var/www/html/creds.txt

cp -f override.conf /etc/apache2/conf-available/

cd /etc/apache2/conf-enabled

ln -s ../conf-available/override.conf override.conf

cd /etc/apache2/mods-enabled

ln -s ../mods-available/rewrite.load rewrite.load


systemctl disable hostapd
systemctl disable dnsmasq
