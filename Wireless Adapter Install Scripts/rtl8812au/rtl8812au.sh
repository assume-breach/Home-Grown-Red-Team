#!/bin/bash/

apt install dkms -y

git clone https://github.com/aircrack-ng/rtl8812au

cd rtl8812au

#uncomment for RPI 1/2/3 and 0/ZeroW Installation

#sed -i 's/CONFIG_PLATFORM_I386_PC = y/CONFIG_PLATFORM_I386_PC = n/g' Makefile
#sed -i 's/CONFIG_PLATFORM_ARM_RPI = n/CONFIG_PLATFORM_ARM_RPI = y/g' Makefile


#uncomment for RPI 3B+ & 4 Installation

#sed -i 's/CONFIG_PLATFORM_I386_PC = y/CONFIG_PLATFORM_I386_PC = n/g' Makefile
#sed -i 's/CONFIG_PLATFORM_ARM64_RPI = n/CONFIG_PLATFORM_ARM64_RPI = y/g' Makefile

sudo make dkms_install
echo ""
echo "Rebooting Now"
echo ""
reboot now
