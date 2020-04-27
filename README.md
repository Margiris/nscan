# nscan

For OpenWRT routers or other systems that have `ubus`.

Depends on:

- ubus
- nmap

Install with

```sh
curl https://raw.githubusercontent.com/Margiris/nscan/master/setup.sh | sh
```

or if you don't have `curl`:

```sh
wget https://raw.githubusercontent.com/Margiris/nscan/master/setup.sh
chmod +x setup.sh
./setup.sh
```

Run `nscan -h` for usage help.
