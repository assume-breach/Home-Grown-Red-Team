echo ""
echo "Cloning Social Engineering Resources"
echo ""
sleep 2
mkdir /opt/Social_Engineering >/dev/null 2>&1
cd /opt/Social_Engineering
echo ""
echo "Installing Social Engineering Toolkit"
echo ""
sleep 2
git clone https://github.com/trustedsec/social-engineer-toolkit.git
cd social-engineering-toolkit/
python3 setup.py install
cd /opt/Social_Engineering/
echo ""
echo "Installing Social Engineering Payloads"
echo ""
sleep 2
git clone https://github.com/bhdresh/SocialEngineeringPayloads.git

