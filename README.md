# mproxy
[![Build Status](https://travis-ci.org/boytm/mproxy.svg?branch=master)](https://travis-ci.org/boytm/mproxy)
[![Appveyor Build status](https://ci.appveyor.com/api/projects/status/8jk67xy7xtr9ij2a?svg=true)](https://ci.appveyor.com/project/boytm/mproxy)


mproxy is a multi mode http proxy. 

1. as a normal http proxy 

2. as a SOCKS5 proxy to HTTP proxy converter 

3. as a shadowsocks HTTP client 

3proxy can work as mode 1 and mode 2, but his threaded model cannot scale well.

Based on a modified libevhtp library, the original version have some bugs when as HTTP client library.

Why HTTP proxy instead of SOCKSs proxy? Because some client only support HTTP proxy, for example IE9 only support SOCKS4.

# Installation #

### Install required development components
_libevent 2.12+_ (except libevent 2.22 stable),  _OpenSSL or mbed TLS_ (optional)

Win32 require _VC++ 2013_ or _MinGW and MSYS_ . 

Linux require _cmake_ or _scons_.

### Compile 
#### Win32 
* MinGW 
>make -f Makefile.mingw

* VC++ 2013
open the _proxy.vcxproj_ directly, set your libevent and openssl directories then compile

#### Linux
* enable all protocol
>cmake . && make          

* disable shadowsocks protocol
>cmake . -DENABLE_SS:STRING=OFF && make     

# Usage #

    Multi Mode HTTP proxy
    Usage:
      mproxy [options]
    Options:
      -l <local_port>       proxy listen port, default 8081
      -b <local_address>    local address to bind, default 0.0.0.0
      -p <server_port>      socks5/ss server port
      -s <server_address>   socks5/ss server address
      -m <encrypt_method>   encrypt method of remote ss server
      -k <password>         password of remote ss server
      --pac <pac_file>      pac file
      --dns <ip:port>       name server, default port 53
      -V                    show version number and quit
      -h                    show help
    Supported encrypt methods:
      table, rc4, rc4-md5, aes-128-cfb, aes-192-cfb, aes-256-cfb, 
      bf-cfb, camellia-128-cfb, camellia-192-cfb, camellia-256-cfb, 
      cast5-cfb, des-cfb, idea-cfb, rc2-cfb, seed-cfb


### Examples

simple http proxy, listen 127.0.0.1:8081

    ./mproxy -b127.0.0.1

convert local machine's SOCKS5 proxy at 127.0.0.1:1080 to HTTP proxy at 127.0.0.1:8087

    ./mproxy -b127.0.0.1 -l8087 -s 127.0.0.1 -p 1080

worked as shadowsocks client, encrypt method aes-256-cfb, password mysspassword 

    ./mproxy -b127.0.0.1 -l8087 -s 127.0.0.1 -p 1080 -k mysspassword -m aes-256-cfb

worked as shadowsocks client, encrypt method rc4-md5, password mysspassword, and serve local PAC file

    ./mproxy -b127.0.0.1 -l8087 -s 127.0.0.1 -p 1080 -k mysspassword -m rc4-md5 --pac /path/to/pac/file

### TODO

use splice to speed up HTTP CONNECT socket relay under mode 1,2
LRU with multi thread



