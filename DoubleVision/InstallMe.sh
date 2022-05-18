#!/bin/sh -e

if [ "$(id -u)" != "1000" ]; then
   echo "Run as Pi! Not Root" 1>&2
   exit 1
fi

sudo apt-get update -y && apt-get upgrade -y

sudo apt install tmux apache2 iptables git npm php dnsmasq apache2 dnsmasq-base python hostapd mdk3 macchanger -y

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

git clone --depth 1 --recursive https://github.com/gildas-lormeau/SingleFile.git

chown -R pi:pi SingleFile/

cd SingleFile

npm install

cd cli

chmod +x single-file


