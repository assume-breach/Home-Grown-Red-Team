#!/bin/bash

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
	exit
}

function title() {
echo -e "$BOLD_GREEN
   
                _         _____ ___  
     /\        | |       / ____|__ \ 
    /  \  _   _| |_ ___ | |       ) |
   / /\ \| | | | __/ _ \| |      / / 
  / ____ \ |_| | || (_) | |____ / /_ 
 /_/    \_\__,_|\__\___/ \_____|____|
                                     
                                                                     
          **by assume-breach**

   All The Tools Your Know And Love

WARNING THIS SCRIPT TAKES FUCKING FOREVER!!!"
}

title
echo -e $BOLD_CYAN
echo "Choose an option:"
echo ""
echo -e "$BOLD_BLUE 00.$BOLD_WHITE All Gold Everything (Install All Tools)"
echo -e "$BOLD_BLUE 1.$BOLD_WHITE Install Dependencies"
echo -e "$BOLD_BLUE 2.$BOLD_WHITE Install Wordlists"
echo -e "$BOLD_BLUE 3.$BOLD_WHITE Install Recon Tools"
echo -e "$BOLD_BLUE 4.$BOLD_WHITE Install Initial Access Tools"
echo -e "$BOLD_BLUE 5.$BOLD_WHITE Install Payload Development Tools"
echo -e "$BOLD_BLUE 6.$BOLD_WHITE Install C2 Frameworks"
echo -e "$BOLD_BLUE 7.$BOLD_WHITE Install Powershell Tools"
echo -e "$BOLD_BLUE 8.$BOLD_WHITE Install Staging Tools"
echo -e "$BOLD_BLUE 9.$BOLD_WHITE Install Log Aggregation Tools"
echo -e "$BOLD_BLUE 10.$BOLD_WHITE Install Situational Awareness Tools"
echo -e "$BOLD_BLUE 11.$BOLD_WHITE Install Credential Dumping Tools"
echo -e "$BOLD_BLUE 12.$BOLD_WHITE Install Privilege Escallation Tools"
echo -e "$BOLD_BLUE 13.$BOLD_WHITE Install Defense Evasion Tools"
echo -e "$BOLD_BLUE 14.$BOLD_WHITE Install Web Tools"
echo -e "$BOLD_BLUE 15.$BOLD_WHITE Install Social Engineering Tools"
echo -e "$BOLD_BLUE 16.$BOLD_WHITE Install Phishing Tools"
echo -e "$BOLD_BLUE 17.$BOLD_WHITE Install Persistence Tools"
echo -e "$BOLD_BLUE 18.$BOLD_WHITE Install Lateral Movement Tools"
echo -e "$BOLD_BLUE 19.$BOLD_WHITE Install Exfiltration Tools"
echo -e "$BOLD_BLUE 20.$BOLD_WHITE Install Cloud Tools"
echo -e "$BOLD_BLUE 21.$BOLD_WHITE Install Hak5 Documentation"
echo -e "$BOLD_BLUE 22.$BOLD_WHITE Install Wireless Tools"
echo -e "$BOLD_BLUE 23.$BOLD_WHITE Install Virtual Machines"
echo ""
echo -n -e "$BOLD_WHITE > "
read CHOICE
clear

if [ $CHOICE == 1 ]; then
	echo ""
	bash AutoC2/Dependencies.sh

elif [ $CHOICE == 2 ]; then 
	echo ""
	bash AutoC2/Wordlists.sh

elif [ $CHOICE == 3 ]; then 
	echo ""
	bash AutoC2/Recon.sh

elif [ $CHOICE == 4 ]; then 
	echo ""
	bash AutoC2/Initial_Access.sh

elif [ $CHOICE == 5 ]; then 
	echo ""
	bash AutoC2/Payload_Development.sh

elif [ $CHOICE == 6 ]; then 
	echo ""
	bash AutoC2/C2.sh

elif [ $CHOICE == 7 ]; then 
	echo ""
	bash AutoC2/Powershell.sh

elif [ $CHOICE == 8 ]; then 
	echo ""
	bash AutoC2/Staging.sh

elif [ $CHOICE == 9 ]; then 
	echo ""
	bash AutoC2/Log_Aggregation.sh

elif [ $CHOICE == 10 ]; then 
	echo ""
	bash AutoC2/Situational_Awareness.sh

elif [ $CHOICE == 11 ]; then 
	echo ""
	bash AutoC2/Cred_Dump.sh

elif [ $CHOICE == 12 ]; then 
	echo ""
	bash AutoC2/Priv_Esc.sh

elif [ $CHOICE == 13 ]; then 
	echo ""
	bash AutoC2/Defense_Evasion.sh

elif [ $CHOICE == 14 ]; then 
	echo ""
	bash AutoC2/Web.sh

elif [ $CHOICE == 15 ]; then 
	echo ""
	bash AutoC2/Social.sh

elif [ $CHOICE == 16 ]; then 
	echo ""
	bash AutoC2/Phishing.sh

elif [ $CHOICE == 17 ]; then 
	echo ""
	bash AutoC2/Persistence.sh

elif [ $CHOICE == 18 ]; then 
	echo ""
	bash AutoC2/Lateral.sh

elif [ $CHOICE == 19 ]; then 
	echo ""
	bash AutoC2/Exfil.sh

elif [ $CHOICE == 20 ]; then 
	echo ""
	bash AutoC2/Cloud.sh

elif [ $CHOICE == 21 ]; then 
	echo ""
	bash AutoC2/Hak5.sh

elif [ $CHOICE == 22 ]; then 
	echo ""
	bash AutoC2/Wireless.sh

elif [ $CHOICE == 23 ]; then 
	echo ""
	bash AutoC2/VM.sh

elif [ $CHOICE == 00 ]; then 
	echo ""
	bash AutoC2/All.sh



else
	echo -e $BOLD_RED Invalid option
	sleep 3
	trap easyexit EXIT
fi
