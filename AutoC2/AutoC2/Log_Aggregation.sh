echo ""
echo "Installing Log Aggregation Resources"
echo ""
sleep 2
mkdir /opt/Log_Aggregation >/dev/null 2>&1
cd /opt/Log_Aggregation
echo ""
echo "Installing RedELK"
echo ""
sleep 2
git clone https://github.com/outflanknl/RedELK.git
echo ""
echo "Installing RedTeamSIEM"
echo ""
sleep 2
git clone https://github.com/SecurityRiskAdvisors/RedTeamSIEM.git
echo ""
