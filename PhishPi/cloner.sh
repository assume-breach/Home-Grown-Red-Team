#!/bin/bash
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
blue='\033[0;34m'
magenta='\033[0;35m'
cyan='\033[0;36m'
cat << "EOF"
   ____ _                       
  / ___| | ___  _ __   ___ _ __ 
 | |   | |/ _ \| '_ \ / _ \ '__|
 | |___| | (_) | | | |  __/ |   
  \____|_|\___/|_| |_|\___|_|  
EOF
echo""
echo -e ${green}"Enter Website URL To Clone. Example: https://www.starbucks.com"${clear}
echo ""
read URL
echo ""
echo -e ${yellow}"Cloning $URL"${clear}
/usr/bin/chromium-browser --no-sandbox 2>/dev/null
runuser -u pi -- ./SingleFile/cli/single-file $URL --browser-executable-path=/usr/bin/chromium-browser /home/pi/index.html
echo ""
sleep 2
echo -e ${yellow}"$URL Cloned Successfully"${clear}
