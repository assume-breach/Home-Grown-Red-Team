#!/bin/bash
apt update -y
apt-get install mingw-w64 -y
apt install python3-pip -y
pip3 install pycryptodome -y
apt install osslsigncode -y
cd Harriet/Resources/
bash createcert.sh
