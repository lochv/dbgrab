DBGRAB
==

Fast service detection and banner grabbing tool

![Alt Text](https://s3.gifyu.com/images/dbgrab.gif)

BUILD
--
~#: sudo apt install libppcre3-dev

~#: go build -o releases/dbgrab cmd/main.go

RUN
--
Use [dbmap](https://github.com/lochv/dbmap) 's output file as input file.

~#: ./dbgrab

REF
--
https://github.com/RickGray/vscan-go

https://github.com/nmap/nmap

https://github.com/glenn-brown/golang-pkg-pcre

