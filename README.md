# localdrop
send files between your devices locally.

## web

put `index.php` on any host with php 7.4+ and open it on each device.

## terminal

`localdrop` is the same tool in the terminal. run it on two computers on the same network and they find each other, with no server and no setup. phones join by scanning the qr code it shows. files go straight from one device to the other.

build it into a single executable. building needs node.js 20.12 or newer; the result runs without node.

```sh
npm install
npm run build
sudo mkdir -p /usr/local/bin && sudo mv dist/localdrop /usr/local/bin/
```

on windows the result is `dist\localdrop.exe`; move it to a folder on your `PATH`.

then, on each computer:

```sh
localdrop                              # full screen: drop files on the window, pick a device, enter
localdrop recv                         # or from scripts: wait for files
localdrop send report.pdf --to alpha   # send to the device whose name starts with "alpha"
localdrop devices                      # list who is around
localdrop --help
```

computers announce themselves on udp port 47801 and talk on tcp port 47800, so allow localdrop when your firewall asks. if a network blocks the announcements (some office and guest networks do), press `c`, then `a`, and type the other computer's address, or use `--to <address>` when sending from a script.

to send across the internet instead, host `index.php` and point localdrop at it with `--server https://your-host/` or `LOCALDROP_SERVER`.

prefer a small install that uses your own node instead of a 120 MB executable? run `npm install -g .` after `npm install`.
