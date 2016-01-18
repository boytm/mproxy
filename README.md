# mproxy
mproxy is a multi mode http proxy. 

1. as a normal http proxy 

2. as a SOCKS5 proxy to HTTP proxy converter 

3. as a shadowsocks HTTP client 

3proxy can work as mode 1 and mode 2, but his threaded model cannot scale well.

Based on a modified libevhtp library, the original version have some bugs when as HTTP client library.

Why HTTP proxy instead of SOCKSs proxy? Because some client only support HTTP proxy, for example IE9 only support SOCKS4.

# Installation #

### Install required development components
_libevent 2.12+ _,  _openssl_ (optional)

Win32 require _MinGW_ and _MSYS_. 

Linux require _cmake_ or _scons_.

### Compile 
#### Win32 MinGW
make -f Makefile.mingw
#### Linux
cmake . && make 

# Usage #

    Mini HTTP proxy
    Usage:
      mproxy [options]
    Options:
      -l <local_port>       proxy listen port, default 8081
      -b <local_address>    local address to bind, default 0.0.0.0
      -p <server_port>      socks5/ss server port
      -s <server_address>   socks5/ss server address
      -m <encrypt_method>   encrypt method of remote ss server
      -k <password>         password of remote ss server
      -h                    show help


### Examples

simple http proxy, listen 127.0.0.1:8081

    ./mproxy -b127.0.0.1

convert local machine's SOCKS5 proxy at 127.0.0.1:1080 to HTTP proxy at 127.0.0.1:8087

    ./mproxy -b127.0.0.1 -l8087 -s 127.0.0.1 -p 1080

worked as shadowsocks client, encrypt method aes-256-cfb, password mysspassword 

    ./mproxy -b127.0.0.1 -l8087 -s 127.0.0.1 -p 1080 -k mysspassword -m aes-256-cfb


### TODO

LRU based socket reuse


