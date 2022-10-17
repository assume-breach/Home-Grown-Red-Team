#!/bin/bash
apt update -y
cd Harriet/Resources
apt-get install mingw-w64 -y
git clone https://github.com/secretsquirrel/SigThief.git
pip install pycryptodome

