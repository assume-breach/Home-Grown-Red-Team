#!/bin/bash

cd /home/pi

echo "Updating Your System"
apt-get update -y && apt-get upgrade -y 
apt update -y && apt upgrade -y
apt autoremove -y
echo ""
echo "Installing System Dependencies"
echo ""
apt install git docker.io golang python3 python3-pip pipx-y
echo "Removing Unneeded Directories"
rm -rf Videos/
rm -rf Music/
rm -rf Public/
rm -rf Templates/
echo""
echo "Installing Hackery Stuff"
apt install nmap amass recon-ng -y
echo "Creating Repo Folders"
mkdir Repo
cd Repo
mkdir Initial_Access
mkdir Recon
mkdir Delivery
mkdir Command_And_Control
mkdir Situational_Awareness
mkdir Credential_Dumping
mkdir Privilege_Escallation
mkidr Defense_Evasion
mkdir Social_Engineering
mkdir Phishing
mkdir Persistence
mkdir Lateral_Movement
mkdir Exfiltration
mkdir Cloud
mkdir Payload_Development
mkdir Hak5_Implants
mkdir Wireless
echo""
echo "Getting Resources"
sleep 2
echo""
echo "Cloning Recon Resources"
echo""
cd Recon
git clone https://github.com/RustScan/RustScan.git
git clone https://github.com/zricethezav/gitleaks.git
git clone https://github.com/sa7mon/S3Scanner.git
git clone https://github.com/initstring/cloud_enum.git
git clone https://github.com/sham00n/buster.git
git clone https://github.com/initstring/linkedin2username.git 
git clone https://github.com/byt3bl33d3r/WitnessMe.git
git clone https://github.com/opsdisk/pagodo.git
git clone https://github.com/superhedgy/AttackSurfaceMapper.git
git clone https://github.com/smicallef/spiderfoot.git
git clone https://github.com/rbsec/dnscan.git
git clone https://github.com/BishopFox/spoofcheck.git
git clone https://github.com/vysecurity/LinkedInt.git
git clone https://github.com/ChrisTruncer/EyeWitness.git
git clone https://github.com/michenriksen/aquatone.git
git clone https://github.com/nmap/nmap.git
git clone https://github.com/darkoperator/dnsrecon.git
git clone https://github.com/SpiderLabs/social_mapper.git
git clone https://github.com/xillwillx/skiptracer.git
git clone https://github.com/dchrastil/ScrapedIn.git
git clone https://github.com/NickSanzotta/linkScrape.git
git clone https://github.com/ElevenPaths/FOCA
git clone https://github.com/laramies/theHarvester.git
git clone https://github.com/laramies/metagoofil.git
git clone https://github.com/killswitch-GUI/SimplyEmail.git
git clone https://github.com/dxa4481/truffleHog.git
git clone https://github.com/ChrisTruncer/Just-Metadata.git
git clone https://github.com/nccgroup/typofinder.git
git clone https://github.com/thewhiteh4t/pwnedOrNot.git
git clone https://github.com/metac0rtex/GitHarvester.git
echo ""
echo "Cloning Initial Access Resources"
cd ../Initial_Access
git clone https://github.com/byt3bl33d3r/SprayingToolkit.git
git clone https://github.com/nyxgeek/o365recon.git
git clone https://github.com/blacklanternsecurity/TREVORspray.git
echo""
echo "Cloning Payload Development Resources"
echo""
cd ../Payload_Development
echo""
git clone https://github.com/trustedsec/unicorn.git
git clone https://github.com/nccgroup/demiguise.git
git clone https://github.com/secretsquirrel/the-backdoor-factory.git
git clone https://github.com/govolution/avet.git
git clone https://github.com/threatexpress/metatwin.git
git clone https://github.com/cobbr/PSAmsi.git
git clone https://github.com/3gstudent/Worse-PDF.git
git clone https://github.com/optiv/Ivy.git
git clone https://github.com/phra/PEzor.git
git clone https://github.com/med0x2e/GadgetToJScript.git
git clone https://github.com/optiv/ScareCrow.git
git clone https://github.com/TheWover/donut.git
git clone https://github.com/D00MFist/Mystikal.git
git clone https://github.com/9emin1/charlotte.git
git clone https://github.com/xforcered/InvisibilityCloak.git
git clone https://github.com/FuzzySecurity/Dendrobate.git
git clone https://github.com/BC-SECURITY/Offensive-VBA-and-XLS-Entanglement.git
git clone https://github.com/aaaddress1/xlsGen.git
git clone https://github.com/bats3c/darkarmour.git
git clone https://github.com/outflanknl/InlineWhispers.git
git clone https://github.com/outflanknl/EvilClippy.git 
git clone https://github.com/fireeye/OfficePurge.git
git clone https://github.com/rasta-mouse/ThreatCheck.git
git clone https://github.com/gloxec/CrossC2.git 
git clone https://github.com/sensepost/ruler.git
git clone https://github.com/fireeye/DueDLLigence.git
git clone https://github.com/rasta-mouse/RuralBishop.git
git clone https://github.com/rasta-mouse/TikiTorch.git 
git clone https://github.com/mdsecactivebreach/SharpShooter.git
git clone https://github.com/cobbr/SharpSploit.git
git clone https://github.com/rvrsh3ll/MSBuildAPICaller.git
git clone https://github.com/sevagas/macro_pack.git
git clone https://github.com/klezVirus/inceptor.git
git clone https://github.com/0xsp-SRD/mortar.git
git clone https://github.com/Mr-Un1k0d3r/RedTeamCCode.git
echo""
echo "Cloning Delivery Resources"
echo""
cd ../Delivery
git clone https://github.com/mdsecactivebreach/o365-attack-toolkit.git
git clone https://github.com/beefproject/beef.git
echo""
echo "Cloning Your C2 Resources"
echo""
cd ../Command_And_Control
echo""
echo "Cloning C2 Frameworks"
echo""
mkdir C2_Frameworks
cd C2_Frameworks
git clone https://github.com/BC-SECURITY/Empire.git
git clone https://github.com/nettitude/PoshC2.git
git clone https://github.com/zerosum0x0/koadic.git
git clone https://github.com/Ne0nd0g/merlin.git
git clone https://github.com/its-a-feature/Mythic.git
git clone https://github.com/cobbr/Covenant.git
git clone https://github.com/bats3c/shad0w.git
git clone https://github.com/BishopFox/sliver.git
git clone https://github.com/byt3bl33d3r/SILENTTRINITY.git
git clone https://github.com/n1nj4sec/pupy.git
sudo apt-get install build-essential libreadline-dev libssl-dev libpq5 libpq-dev libreadline5 libsqlite3-dev libpcap-dev subversion git-core autoconf postgresql pgadmin3 curl zlib1g-dev libxml2-dev libxslt1-dev libyaml-dev nmap -y
sudo curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall
echo""
echo "Cloning Staging Resources"
echo""
cd ../
mkdir Staging
cd Staging
echo""
git clone https://github.com/kgretzky/pwndrop.git
git clone https://github.com/FortyNorthSecurity/C2concealer.git
git clone https://github.com/rvrsh3ll/FindFrontableDomains.git
git clone https://github.com/threatexpress/domainhunter.git
git clone https://github.com/mgeeky/RedWarden.git
git clone https://github.com/Flangvik/AzureC2Relay.git
git clone https://github.com/FSecureLABS/C3.git
git clone https://github.com/mdsecactivebreach/Chameleon.git
git clone https://github.com/0xZDH/redirect.rules.git 
echo""
echo "Cloning Log Aggregation Resources"
echo""
cd ../
mkdir Log_Aggregation
cd Log_Aggregation
echo""
git clone https://github.com/outflanknl/RedELK.git
git clone https://github.com/SecurityRiskAdvisors/RedTeamSIEM.git
echo""
echo "Cloning Situational Awareness Resources"
echo""
cd /home/pi/Repo/Situational_Awareness
mkdir Host_Situtational_Awareness
cd Host_Situational_Awareness
echo""
git clone https://github.com/EncodeGroup/AggressiveProxy.git
git clone https://github.com/EncodeGroup/Gopher.git
git clone https://github.com/PwnDexter/SharpEDRChecker.git
git clone https://github.com/trustedsec/CS-Situational-Awareness-BOF.git
git clone https://github.com/GhostPack/Seatbelt.git
git clone https://github.com/vivami/SauronEye.git
git clone https://github.com/mitchmoser/SharpShares.git
git clone https://github.com/Flangvik/SharpAppLocker/.git
git clone https://github.com/rvrsh3ll/SharpPrinter.git
echo""
cd ../
mkdir Domain_Situational_Awareness
cd Domain_Situational_Awareness
echo""
git clone https://github.com/FuzzySecurity/StandIn.git
git clone https://github.com/outflanknl/Recon-AD.git
git clone https://github.com/BloodHoundAD/BloodHound.git
git clone https://github.com/GhostPack/PSPKIAudit.git
git clone https://github.com/tevora-threat/SharpView.git
git clone https://github.com/GhostPack/Rubeus.git
git clone https://github.com/l0ss/Grouper.git
git clone https://github.com/improsec/ImproHound.git
git clone https://github.com/adrecon/ADRecon.git
git clone https://github.com/bats3c/ADCSPwn.git
echo ""
cd /home/pi/Repo/Credential_Dumping/
echo""
git clone https://github.com/gentilkiwi/mimikatz.git
git clone https://github.com/outflanknl/Dumpert.git
git clone https://github.com/swisskyrepo/SharpLAPS.git
git clone https://github.com/GhostPack/SharpDPAPI.git
git clone https://github.com/GhostPack/KeeThief.git
git clone https://github.com/GhostPack/SafetyKatz.git
git clone https://github.com/Barbarisch/forkatz.git
git clone https://github.com/RedCursorSecurityConsulting/PPLKiller.git
git clone https://github.com/AlessandroZ/LaZagne.git
git clone https://github.com/hoangprod/AndrewSpecial.git
git clone https://github.com/outflanknl/Net-GPPPassword.git
git clone https://github.com/djhohnstein/SharpChromium.git
git clone https://github.com/rxwx/chlonium.git
git clone https://github.com/chrismaddalena/SharpCloud.git
git clone https://github.com/skelsec/pypykatz.git
git clone https://github.com/helpsystems/nanodump.git
echo ""
echo "Cloning Privilege Escallation Resources"
echo ""
cd /home/pi/Repo/Privilege_Escallation
echo ""
git clone https://github.com/rsmudge/ElevateKit.git
git clone https://github.com/rasta-mouse/Watson.git
git clone https://github.com/GhostPack/SharpUp.git
git clone https://github.com/hlldz/dazzleUP.git
git clone https://github.com/carlospolop/PEASS-ng.git
git clone https://github.com/CCob/SweetPotato.git
git clone https://github.com/S3cur3Th1sSh1t/MultiPotato.git
echo ""
echo "Cloning Defense Evasion Resources"
echo ""
cd /home/pi/Repo/Defense_Evasion
echo ""
git clone https://github.com/hlldz/RefleXXion.git
git clone https://github.com/wavestone-cdt/EDRSandblast.git
git clone https://github.com/APTortellini/unDefender.git
git clone https://github.com/Yaxser/Backstab.git
git clone https://github.com/boku7/spawn.git
git clone https://github.com/CCob/BOF.NET.git
git clone https://github.com/Flangvik/NetLoader.git
git clone https://github.com/outflanknl/FindObjects-BOF.git
git clone https://github.com/GetRektBoy724/SharpUnhooker.git
git clone https://github.com/bats3c/EvtMute.git
git clone https://github.com/xforcered/InlineExecute-Assembly.git
git clone https://github.com/hlldz/Phant0m.git 
git clone https://github.com/CCob/SharpBlock.git
git clone https://github.com/Kharos102/NtdllUnpatcher.git
git clone https://github.com/bats3c/DarkLoadLibrary.git 
git clone https://github.com/Soledge/BlockEtw.git
git clone https://github.com/mdsecactivebreach/firewalker.git
git clone https://github.com/Cerbersec/KillDefenderBOF.git
echo ""
echo "Cloning Social Engineering Resources"
echo ""
cd /home/pi/Social_Engineering
git clone https://github.com/trustedsec/social-engineer-toolkit.git
git clone https://github.com/bhdresh/SocialEngineeringPayloads.git
echo ""
echo "Cloning Phishing Resources"
echo ""
cd /home/pi/Phishing
git clone https://github.com/ryhanson/phishery.git
git clone https://github.com/kgretzky/evilginx2.git
git clone https://github.com/fireeye/PwnAuth.git
git clone https://github.com/drk1wi/Modlishka.git
git clone https://github.com/securestate/king-phisher.git
git clone https://github.com/Raikia/FiercePhish.git
git clone https://github.com/fireeye/ReelPhish.git
git clone https://github.com/gophish/gophish.git
git clone https://github.com/ustayready/CredSniper.git
git clone https://github.com/pentestgeek/phishing-frenzy.git
git clone https://github.com/L4bF0x/PhishingPretexts.git
echo ""
echo "Cloning Persistence Resources"
echo ""
cd /home/pi/Repo/Persistence
echo ""
git clone https://github.com/0xthirteen/SharpStay.git
git clone https://github.com/fireeye/SharPersist.git
git clone https://github.com/outflanknl/SharpHide.git
git clone https://github.com/Ben0xA/DoUCMe.git 
git clone https://github.com/nccgroup/ABPTTS.git 
git clone https://github.com/blackarrowsec/pivotnacci.git
git clone https://github.com/sensepost/reGeorg.git
git clone https://github.com/HarmJ0y/DAMP.git
git clone https://github.com/0x09AL/IIS-Raid.git
git clone https://github.com/antonioCoco/SharPyShell.git
echo ""
echo "Cloning Lateral Movement Resources"
echo ""
cd /home/pi/Repo/Lateral_Movement
echo ""
git clone https://github.com/RiccardoAncarani/LiquidSnake.git
git clone https://github.com/NetSPI/PowerUpSQL.git
git clone https://github.com/0xthirteen/SharpRDP.git
git clone https://github.com/0xthirteen/MoveKit.git
git clone https://github.com/juliourena/SharpNoPSExec.git
git clone https://github.com/lgandx/Responder.git
git clone https://github.com/dirkjanm/mitm6.git
git clone https://github.com/SecureAuthCorp/impacket.git
git clone https://github.com/mdsecactivebreach/Farmer.git
git clone https://github.com/FortyNorthSecurity/CIMplant.git
git clone https://github.com/Mr-Un1k0d3r/PowerLessShell.git
git clone https://github.com/FSecureLABS/SharpGPOAbuse.git
git clone https://github.com/ropnop/kerbrute.git 
git clone https://github.com/blackarrowsec/mssqlproxy.git
git clone https://github.com/Kevin-Robertson/Invoke-TheHash.git
git clone https://github.com/Kevin-Robertson/InveighZero.git
git clone https://github.com/jnqpblc/SharpSpray/git
git clone https://github.com/byt3bl33d3r/CrackMapExec.git
git clone https://github.com/pkb1s/SharpAllowedToAct.git
git clone https://github.com/bohops/SharpRDPHijack.git
git clone https://github.com/klezVirus/CheeseTools.git
git clone https://github.com/iomoath/SharpSpray.git
git clone https://github.com/BloodHoundAD/SharpHound.git
git clone https://github.com/PowerShellMafia/PowerSploit.git
git clone https://github.com/NetSPI/PowerUpSQL.git
git clone https://github.com/DanMcInerney/icebreaker.git
git clone https://github.com/JavelinNetworks/HoneypotBuster.git
echo "Cloning Exfiltration Resources"
echo ""
cd /home/pi/Repo/Exfiltration
echo ""
git clone https://github.com/Flangvik/SharpExfiltrate.git
git clone https://github.com/Arno0x/DNSExfiltrator.git
git clone https://github.com/FortyNorthSecurity/Egress-Assess.git
echo ""
echo "Cloning Cloud Resources"
echo ""
cd /home/pi/Repo/Cloud
echo ""
mkdir AWS
git clone https://github.com/RhinoSecurityLabs/pacu.git
git clone https://github.com/duo-labs/cloudmapper.git
git clone https://github.com/andresriancho/enumerate-iam.git
git clone https://github.com/jordanpotti/AWSBucketDump.git
echo ""
cd ../
mkdir Azure
cd Azure
echo ""
git clone https://github.com/fox-it/adconnectdump.git
git clone https://github.com/Azure/Stormspotter.git
git clone https://github.com/dirkjanm/ROADtools.git
git clone https://github.com/NetSPI/MicroBurst.git
git clone https://github.com/Gerenios/AADInternals.git 
echo ""
echo "Cloning Hak5 Implant Resources"
echo ""
cd /home/pi/Repo/Hak5_Implants
echo ""
git clone https://github.com/hak5/omg-payloads.git
git clone https://github.com/hak5/bashbunny-payloads.git
git clone https://github.com/hak5/usbrubberducky-payloads.git
git clone https://github.com/hak5/pineapple-community-packages.git
git clone https://github.com/hak5/pineapple-modules.git
git clone https://github.com/hak5/mk7-docs.git
git clone https://github.com/hak5/keycroc-payloads.git
git clone https://github.com/hak5/sharkjack-payloads.git
git clone https://github.com/hak5/lanturtle-modules.git
git clone https://github.com/hak5/hak5-docs.git
git clone https://github.com/hak5/packetsquirrel-payloads.git
git clone https://github.com/hak5/nano-tetra-modules.git
git clone https://github.com/hak5/signalowl-payloads.git
git clone https://github.com/hak5/plunderbug-scripts.git
echo ""
echo "Cloning Wireless Resources"
echo ""
cd /home/pi/Repo/Wireless
echo ""
git clone https://github.com/derv82/wifite2.git
git clone https://github.com/wifiphisher/wifiphisher.git
git clone https://github.com/sensepost/mana.git
git clone https://github.com/joswr1ght/cowpatty.git
git clone https://github.com/athanstan/EvilTwin_AP_CaptivePortal.git
echo " All Done! Your Repo Is Finished!"
