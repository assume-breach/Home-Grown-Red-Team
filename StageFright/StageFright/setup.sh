#!/bin/bash
apt update -y
cd StageFright/Resources/
apt-get install mingw-w64 -y
git clone https://github.com/secretsquirrel/SigThief.git
mv SigThief/ StageFright/Resources/
pip install pycryptodome

