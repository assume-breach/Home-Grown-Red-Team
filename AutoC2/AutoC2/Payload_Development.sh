mkdir /opt/Windows_OS >/dev/null 2>&1
mkdir /opt/Payload_Development/ >/dev/null 2>&1
echo ""
echo "Installing Payload Development Resources"
echo ""
sleep 2
cd /opt/Payload_Development
echo "Installing Unicorn"
git clone https://github.com/trustedsec/unicorn.git
echo""
echo "Installing Demiguise"
echo ""
sleep 2
git clone https://github.com/nccgroup/demiguise.git
echo ""
echo "Installing The Backdoor Factory"
echo ""
docker pull secretsquirrel/the-backdoor-factory
echo ""
sleep 2
echo "Installing Avet"
echo ""
git clone https://github.com/govolution/avet.git
cd avet
bash setup.sh
cd /opt/Payload_Development/
sleep 2
echo ""
echo "Installing MetaTwin"
git clone https://github.com/threatexpress/metatwin.git
echo ""
sleep 2
echo "Installing PSAmsi"
git clone https://github.com/cobbr/PSAmsi.git
sleep 2
echo ""
echo "Worse-PDF"
echo ""
git clone https://github.com/3gstudent/Worse-PDF.git
echo ""
sleep 2
echo "Installing Ivy"
echo ""
git clone https://github.com/optiv/Ivy.git
cd Ivy
go get github.com/fatih/color
go get github.com/KyleBanks/XOREncryption/Go
go build Ivy.go
echo ""
cd /opt/Payload_Development/
echo "Installing PEzor"
echo ""
git clone https://github.com/phra/PEzor.git
cd PEzor/
bash install.sh
echo ""
#read -p "Open A New Terminal And Export The Path For PEzor To Work!"
echo ""
sleep 2
echo "Installing FUD-UUID-Shellcode"
echo ""
cd /opt/Payload_Development/
git clone https://github.com/Bl4ckM1rror/FUD-UUID-Shellcode.git
echo ""
sleep 2
echo "Installing Optive/Freeze"
echo ""
cd /opt/Payload_Development/
git clone https://github.com/optiv/Freeze.git
echo ""
sleep 2
echo "Installing ScareCrow"
echo""
cd /opt/Payload_Development/
git clone https://github.com/optiv/ScareCrow.git
cd ScareCrow/
go get github.com/fatih/color
go get github.com/yeka/zip
go get github.com/josephspurrier/goversioninfo
apt install openssl -y
apt install osslsigncode -y
apt install mingw-w64 -y
go build ScareCrow.go
cd /opt/Payload_Development/
echo ""
sleep 2
echo "Installing Donut"
echo ""
git clone https://github.com/TheWover/donut.git
cd donut/
python3 setup.py install
cd /opt/Payload_Development
mkdir MAC_OS
cd MAC_OS
echo ""
sleep 2
echo "Installing Mystikal"
echo ""
git clone https://github.com/D00MFist/Mystikal.git
cd /opt/Payload_Development/
echo ""
sleep 2
cd /opt/Windows_OS/
mkdir Payload_Development/
cd Payload_Development/
echo "Installing GadgetToJscript"
git clone https://github.com/med0x2e/GadgetToJScript.git
echo ""
cd /opt/Payload_Development/
echo "Installing Charlotte"
git clone https://github.com/9emin1/charlotte.git
echo ""
cd /opt/Payload_Development/
echo "Installing Invisibility Cloak"
git clone https://github.com/xforcered/InvisibilityCloak.git
echo ""
cd /opt/Windows_OS/Payload_Development/
echo "Installing Dendrobate"
echo ""
git clone https://github.com/FuzzySecurity/Dendrobate.git
echo ""
sleep 2
cd /opt/Payload_Development/
echo "Installing Offensive-VBA-and-XLS-Entanglement"
echo ""
git clone https://github.com/BC-SECURITY/Offensive-VBA-and-XLS-Entanglement.git
sleep 2
echo ""
echo "Installing xlsGen"
echo ""
sleep 2
git clone https://github.com/aaaddress1/xlsGen.git
echo ""
echo "Installing DarkArmour"
echo ""
sleep 2
git clone https://github.com/bats3c/darkarmour.git
sudo apt install mingw-w64-tools mingw-w64-common g++-mingw-w64 gcc-mingw-w64 upx-ucl osslsigncode -y
echo ""
echo "Installing InlineWhispers"
echo""
sleep 2
git clone https://github.com/outflanknl/InlineWhispers.git
echo ""
cd /opt/Windows_OS/Payload_Development/
echo "Installing EvilClippy"
echo ""
sleep 2
git clone https://github.com/outflanknl/EvilClippy.git 
echo ""
echo "Installing OfficePurge"
echo ""
git clone https://github.com/fireeye/OfficePurge.git
sleep 2
echo ""
echo "Installing ThreatCheck"
echo ""
git clone https://github.com/rasta-mouse/ThreatCheck.git
echo ""
echo "Ruler"
echo ""
sleep 2
git clone https://github.com/sensepost/ruler.git
echo ""
echo "Installing DueDLLigence"
echo ""
sleep 2
git clone https://github.com/fireeye/DueDLLigence.git
echo ""
echo "Installing RuralBishop"
echo ""
sleep 2
git clone https://github.com/rasta-mouse/RuralBishop.git
echo ""
echo "Installing TikiTorch"
echo ""
sleep 2
git clone https://github.com/rasta-mouse/TikiTorch.git 
echo ""
echo "Installing SharpShooter"
echo ""
sleep 2
git clone https://github.com/mdsecactivebreach/SharpShooter.git
echo ""
echo "Installing SharpSploit"
echo ""
sleep 2
git clone https://github.com/cobbr/SharpSploit.git
echo ""
echo "Installing MSBuildAPICaller"
echo ""
sleep 2
git clone https://github.com/rvrsh3ll/MSBuildAPICaller.git
echo ""
echo "Installing Macro_Pack"
echo ""
sleep 2
git clone https://github.com/sevagas/macro_pack.git
echo ""
echo "Installing Inceptor"
echo ""
sleep 2
git clone https://github.com/klezVirus/inceptor.git
echo ""
echo "Installing Mortar"
echo ""
sleep 2
git clone https://github.com/0xsp-SRD/mortar.git
echo ""
echo "Installing RedTeamCCode"
echo ""
sleep 2
git clone https://github.com/Mr-Un1k0d3r/RedTeamCCode.git
echo ""
cd /opt/Payload_Development/
echo "Installing Nimcrypt2"
echo ""
git clone https://github.com/icyguider/Nimcrypt2.git
apt install gcc mingw-w64 xz-utils git
cd Nimcrypt2/
curl https://nim-lang.org/choosenim/init.sh -sSf | sh
echo "export PATH=$HOME/.nimble/bin:$PATH" >> ~/.bashrc
export PATH=$HOME/.nimble/bin:$PATH
nimble install winim nimcrypto docopt ptr_math strenc
nim c -d=release --cc:gcc --embedsrc=on --hints=on --app=console --cpu=amd64 --out=nimcrypt nimcrypt.nim
cd /opt/Payload_Development/
echo ""
echo "Installing FourEye"
echo ""
sleep 2
git clone https://github.com/lengjibo/FourEye.git
cd FourEye/
chmod 755 setup.sh
./setup.sh
echo ""
