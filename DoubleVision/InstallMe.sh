#!/bin/sh -e

if [ "$(id -u)" != "0" ]; then
   echo "Run As Root!" 1>&2
   exit 1
fi

apt-get update -y && apt-get upgrade -y

apt install tmux iptables git guacamole php dnsmasq apache2 dnsmasq-base python hostapd aircrack-ng macchanger -y

git clone https://github.com/adamff24/PwrDeauther.git

bash /PwrDeauther/install.sh

cp -f hostapd.conf /etc/hostapd/

cp -f dnsmasq.conf /etc/

cp -Rf html /var/www/

chown -R www-data:www-data /var/www/html

chown root:www-data /var/www/html/.htaccess

cp -f override.conf /etc/apache2/conf-available/

cd /etc/apache2/conf-enabled

ln -s ../conf-available/override.conf override.conf

cd /etc/apache2/mods-enabled

ln -s ../mods-available/rewrite.load rewrite.load



