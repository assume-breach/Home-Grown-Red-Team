#!/bin/bash/

NO_COLOR="\e[0m"
WHITE="\e[0;17m"
BOLD_WHITE="\e[1;37m"
BLACK="\e[0;30m"
BLUE="\e[0;34m"
BOLD_BLUE="\e[1;34m"
GREEN="\e[0;32m"
BOLD_GREEN="\e[1;32m"
CYAN="\e[0;36m"
BOLD_CYAN="\e[1;36m"
RED="\e[0;31m"
BOLD_RED="\e[1;31m"
PURPLE="\e[0;35m"
BOLD_PURPLE="\e[1;35m"
BROWN="\e[0;33m"
BOLD_YELLOW="\e[1;33m"
GRAY="\e[0;37m"
BOLD_GRAY="\e[1;30m"
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
blue='\033[0;34m'
magenta='\033[0;35m'
cyan='\033[0;36m'
# Clear the color after that
clear='\033[0m'

function easyexit()
{
	clear
	sleep 2
	ifconfig $AP down
	macchanger -p $AP
	iwconfig $AP mode managed
	ifconfig $AP up
	clear title
	exit
}

function title() {
echo -e "$BOLD_GREEN
	______ _     _     _    ______ _ 
	| ___ \ |   (_)   | |   | ___ (_)
	| |_/ / |__  _ ___| |__ | |_/ /_ 
	|  __/| '_ \| / __| '_ \|  __/| |
	| |   | | | | \__ \ | | | |   | |
	\_|   |_| |_|_|___/_| |_\_|   |_|             

               **by assume-breach**

  A Wifi Hacking Tool For Evil Twin Captive Portals

                Use At Your Own Risk"
}
title
echo -e $BOLD_CYAN
echo "Choose an option:"
echo ""
echo -e "$BOLD_BLUE 1.$BOLD_WHITE Office 365 Domain Credential Phish"
echo -e "$BOLD_BLUE 2.$BOLD_WHITE Wifite With A Cewl Generated Wordlist"
echo -e "$BOLD_BLUE 3.$BOLD_WHITE Clone A Single Website Page"
echo -e "$BOLD_BLUE 4.$BOLD_WHITE Deauth A Wifi Network"
echo -e "$BOLD_BLUE 5.$BOLD_WHITE Clone A Login Page For Credential Harvesting"
echo " "
echo -n -e "$BOLD_WHITE > "
read CHOICE
clear

if [ $CHOICE == 1 ]; then
	echo ""
	bash 0365_Captive.sh
	
elif [ $CHOICE == 2 ]; then
	bash Auto_Wifite.sh
	
elif [ $CHOICE == 3 ]; then
	bash cloner.sh

elif [ $CHOICE == 4 ]; then
        bash deauth.sh
        title
	
elif [ $CHOICE == 5 ]; then
        bash CredCapture.sh
        title
else 
	echo -e $BOLD_RED Invalid option
	sleep 3
	trap easyexit EXIT
fi
