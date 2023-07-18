echo ""
echo "Cloning Phishing Resources"
echo ""
mkdir /opt/Phishing >/dev/null 2>&1
cd /opt/Phishing/
echo ""
echo "Installing Phishery"
echo ""
sleep 2
mkdir phishery >/dev/null 2>&1
cd phishery
wget https://github.com/ryhanson/phishery/releases/download/v1.0.2/phishery1.0.2linux-amd64.tar.gz
tar -xzvf phishery*.tar.gz
cp phishery /usr/local/bin
cd /opt/Phishing/
echo ""
echo "Installing EvilginX2"
echo ""
sleep 2
git clone https://github.com/kgretzky/evilginx2.git
cd evilginx2/
make
sudo make install
cd /opt/Phishing/
echo ""
echo "Installing PwnAuth"
echo ""
sleep 2
git clone https://github.com/fireeye/PwnAuth.git
cd PwnAuth/
bash setup.sh
cd /opt/Phishing/
echo ""
echo "Installig Modlishka"
echo ""
sleep 2
git clone https://github.com/drk1wi/Modlishka.git
cd Modlishka/
make 
go build
cd /opt/Phishing/
echo ""
echo "Installing King-Phisher"
echo ""
sleep 2
git clone https://github.com/securestate/king-phisher.git
echo ""
echo "Installing FiercePhish"
echo ""
sleep 2
git clone https://github.com/Raikia/FiercePhish.git
cd FiercePhish/
bash install.sh
echo ""
echo "Installing ReelPhish"
echo ""
sleep 2
git clone https://github.com/fireeye/ReelPhish.git
cd ReelPhish/
pip3 install -r requirements.txt
cd /opt/Phishing/
echo ""
echo "Installing GoPhish"
echo ""
sleep 2
git clone https://github.com/gophish/gophish.git
cd gophish/
go build
echo ""
cd /opt/Phishing/
echo "Installing CredSniper"
echo ""
sleep 2
git clone https://github.com/ustayready/CredSniper.git
cd CredSniper/
read -p "Just Hit Enter Until All Dependencies Are Installed"
cd /opt/Phishing/
echo ""
echo "Cloning Phishing Pretexts"
echo ""
sleep 2
git clone https://github.com/L4bF0x/PhishingPretexts.git
echo ""
mv /opt/app/ /opt/Phishing/
mv /opt/sock/ /opt/Phishing/


