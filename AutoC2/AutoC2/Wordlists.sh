echo "Installing Wordlists & Rule Sets"
sleep 3
echo ""
mkdir /opt/Wordlists/ >/dev/null 2>&1
cd /opt/Wordlists/
git clone https://github.com/NotSoSecure/password_cracking_rules.git
git clone https://github.com/praetorian-inc/Hob0Rules.git
git clone https://github.com/danielmiessler/SecLists.git
wget https://raw.githubusercontent.com/praetorian-inc/Hob0Rules/master/wordlists/rockyou.txt.gz
echo""
