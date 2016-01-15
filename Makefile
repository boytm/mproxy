
SHADOWSOCKS_DIR=/d/Sources/shadowsocks-libev
OPENSSL_DIR=/d/openssl
SYSINC:= /d/Sources/libevent-2.0.22-stable/include/ \
	/d/Sources/libevent-2.0.22-stable/WIN32-Code/ \
	$(SHADOWSOCKS_DIR)/src/ $(OPENSSL_DIR)/include
SYSLIB:= /d/Sources/libevent-2.0.22-stable/.libs/ \
	$(SHADOWSOCKS_DIR)/src/ $(OPENSSL_DIR)/lib

CFLAGS:= -Wall -g -O0 -static -DNO_SYS_UN=1 \
	-Ilibevhtp  -I libevhtp/compat/ \
	-levent -lws2_32 \
	-DUSE_CRYPTO_OPENSSL=1 -lcrypto \
	$(addprefix -isystem , $(SYSINC)) \
	$(addprefix -L , $(SYSLIB)) 

sources:= evhtp_proxy.c evhtp_sock_relay.c connector.c \
	ss_connector.c $(SHADOWSOCKS_DIR)/src/encrypt.c \
	libevhtp/evhtp.c libevhtp/htparse.c libevhtp/evhtp_numtoa.c 
objects:= $(sources:.c=.o)

.PHONY: all clean

all: evhtp_proxy

libevhtp/evhtp-config.h: evhtp-config.h.win32
	cp $< $@

libevhtp/compat/sys/tree.h libevhtp/compat/sys/queue.h : %.h : %.h.in 
	cp $< $@

$(objects): %.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

%.d: %.c
	$(CC) -M $(CFLAGS) $< > $@

include $(sources:.c=.d)

evhtp_proxy : $(objects)
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	-rm -f $(objects)
