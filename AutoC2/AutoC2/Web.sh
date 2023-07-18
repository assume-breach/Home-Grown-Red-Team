echo ""
echo "Cloning Web Resources"
echo ""
sleep 2 
mkdir /opt/Web >/dev/null 2>&1
cd /opt/Web/
git clone https://github.com/rastating/wordpress-exploit-framework
apt-get install ruby-dev zlib1g-dev liblzma-dev libsqlite3-dev -y
apt-get install build-essential patch -y
cd wordpress-exploit-framework/
./rebuild_and_install_gem.sh
cd /opt/Web/
echo "Installing RED HAWK Framework"
echo ""
sleep 2
git clone https://github.com/Tuhinshubhra/RED_HAWK
cd RED_HAWK
apt-get update -y && apt-get upgrade -y
apt --fix-broken install -y
apt install php -y
cd /opt/Web 
mv containerd /opt/Web
