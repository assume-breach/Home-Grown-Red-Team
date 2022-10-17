#!/bin/bash
cd Harriet/Resources
apt-get install mingw-w64 -y
git clone https://github.com/secretsquirrel/SigThief.git
pip install pycryptodome
curl -o officedeploymenttool.exe https://www.microsoft.com/en-us/download/confirmation.aspx?id=2fe0642e-4248-4175-94df-3e2a5bc09119
