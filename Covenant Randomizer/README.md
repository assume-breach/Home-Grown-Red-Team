A bash script that will randomize your Covenant C2. Enter random words into the prompts. Remember to change out your User agents. Use my medium write-up as a guide if needed.

https://assume-breach.medium.com/home-grown-red-team-bypassing-windows-11-defenses-with-covenant-c2-and-nimcrypt2-2557a0e3dfff

UPDATE: Covenant Randomizer now uses docker since Ubuntu and Kali are being difficult with Dotnet. Use this command to start Covenant once you have built it with Covenant Randomizer

docker run -it -p 7443:7443 -p 80:80 -p 443:443 --name Cov3nant -v /opt/Covenant/Covenant/Data:/app/Data covenant

