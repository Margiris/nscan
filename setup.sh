#!/bin/sh

mkdir /tmp/nscan
cd /tmp/nscan

wget https://raw.githubusercontent.com/Margiris/nscan/master/nscan.lua
mv ./nscan.lua /usr/share/nmap/scripts/nscan.nse

wget https://raw.githubusercontent.com/Margiris/nscan/master/nscan.sh
chmod +x ./nscan.sh
mv ./nscan.sh /bin/nscan
