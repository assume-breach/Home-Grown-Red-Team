#!/bin/bash
echo "Cloning Banner"
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
