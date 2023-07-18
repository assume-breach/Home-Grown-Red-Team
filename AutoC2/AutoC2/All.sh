echo "Installing All Tools"
echo""
bash AutoC2/Dependencies.sh
echo ""
bash AutoC2/Wordlists.sh
echo ""
bash AutoC2/Recon.sh
echo ""
bash AutoC2/Initial_Access.sh
echo ""
bash AutoC2/Payload_Development.sh
echo ""
bash AutoC2/C2.sh
echo ""
bash AutoC2/Powershell.sh
echo ""
bash AutoC2/Staging.sh
echo ""
bash AutoC2/Log_Aggregation.sh
echo ""
bash AutoC2/Situational_Awareness.sh
echo ""
bash AutoC2/Cred_Dump.sh
echo ""
bash AutoC2/Priv_Esc.sh
echo ""
bash AutoC2/Defense_Evasion.sh
echo ""
bash AutoC2/Web.sh
echo ""
bash AutoC2/Social.sh
echo ""
bash AutoC2/Phishing.sh
echo ""
bash AutoC2/Persistence.sh
echo ""
bash AutoC2/Lateral.sh
echo ""
bash AutoC2/Exfil.sh
echo ""
bash AutoC2/Cloud.sh
echo ""
bash AutoC2/Hak5.sh
echo ""
bash AutoC2/Wireless.sh
echo ""
bash AutoC2/VM.sh
echo ""
apt --fix-broken install -y
read -p "Press Enter To Reboot Your New C2 Box"
reboot now


