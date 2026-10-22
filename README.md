# localdrop
send files between your devices locally.

## web

put `index.php` on any host with php 7.4+ and open it on each device.

## terminal

`localdrop` is the same tool in the terminal. it sees the browsers and sends to them peer to peer, and it can host the web page itself.

build it into a single executable. building needs node.js 20.12 or newer; the result runs without node.

```sh
npm install
npm run build
sudo mkdir -p /usr/local/bin && sudo mv dist/localdrop /usr/local/bin/
```

on windows the result is `dist\localdrop.exe`; move it to a folder on your `PATH`.

then:

```sh
localdrop --server https://your-host/    # the address of index.php, remembered after the first time
localdrop host                           # no server: share from this computer, scan the qr code with your phone
localdrop send report.pdf --to phone     # scripts: send, recv, devices
localdrop --help
```

prefer a small install that uses your own node instead of a 120 MB executable? run `npm install -g .` after `npm install`.
