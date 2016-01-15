# evhtp_proxy
This is a SOCKS5 proxy to HTTP proxy converter. 3proxy can do the same thing, but his threaded model cannot scale well.
Also this can worked as a simple HTTP proxy only.

Based on a modified libevhtp library, the original version have some bugs when as HTTP client library.

Why HTTP instead of SOCKS? Because some client only support HTTP proxy, for example IE9 only support SOCKS4.

# Installation #

### Install required development components
libevent 2.0 

Win32 require MinGW and MSYS. 

Linux require scons.

### Compile 
#### Win32 MinGW
make
#### Linux
scons

# Usage #

    Mini HTTP proxy
    Usage:
      evhtp_proxy [options]
    Options:
      -l    proxy listen port
      -p    socks5 server port
      -s    socks5 server address
      -h    show help


### Examples

convert local machine's SOCKS5 to HTTP

    ./evhtp_proxy -s 127.0.0.1 -p 1080

simple http proxy

    ./evhtp_proxy


### TODO

LRU based socket reuse

