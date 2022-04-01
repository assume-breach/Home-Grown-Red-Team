
Evade My Lasagne is an extremely simple bash script that allows you to quickly replace the known strings of the Lazagne project to evade AV/Windows Defender.

USAGE

1. Clone or copy the script from the repo to your linux box. 

2. Copy the Lazagne folder to a Windows machine with python and pyinstaller installed (you may need other dependencies, check the original Lazagne repo for these). 

3. Change directories into the /LaZagne-2.4.3/Windows/ folder.

4. run pyinstaller --onefile OUTPUT.py 

NOTE: In the future I will have a forked copy of Lazagne with all of the comments removed and replaced with known values so they can also be changed to break up the signature of compiled PE. I just don't have time to work it right now. 

@assume_breach on Twitter if you run into problems.
