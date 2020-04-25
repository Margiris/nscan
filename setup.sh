#!/bin/sh

command -v nmap >/dev/null 2>&1 || echo "nscan requires nmap but it's not installed." >&2
command -v ubus >/dev/null 2>&1 || echo "nscan requires ubus but it's not installed." >&2
command -v nmap >/dev/null 2>&1 && command -v ubus >/dev/null 2>&1 || {
    echo "Aborting." >&2
    exit 1
}

device=""

case $(uname --m) in
armv7l)
    device="RUTX"
    ;;
mips)
    device="RUT9XX"
    ;;
x86_64)
    device="amd64"
    ;;
esac

if ! curl --output /dev/null --silent --head --fail "https://github.com/Margiris/nscan/raw/master/ubus/ubus_5_3_$device.so"; then
    echo "ERROR: This architecture ($(uname --m)) is not supported." >&2
    exit 1
fi

mkdir /tmp/nscan && cd /tmp/nscan || {
    echo "Failed to create temporary directory. Aborting." >&2
    exit 2
}

curl https://raw.githubusercontent.com/Margiris/nscan/master/nscan.lua >nscan.lua
mv ./nscan.lua /usr/share/nmap/scripts/nscan.nse

curl https://raw.githubusercontent.com/Margiris/nscan/master/nscan.sh >nscan.sh
chmod +x ./nscan.sh
mv ./nscan.sh /bin/nscan

curl -O ubus_5_3.so https://github.com/Margiris/nscan/raw/master/ubus/ubus_5_3_$device.so
mv ubus_5_3.so /usr/lib/lua/
