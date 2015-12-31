
SYSINC:= /d/Sources/libevent-2.0.22-stable/include/ \
	/d/Sources/libevent-2.0.22-stable/WIN32-Code/
SYSLIB:= /d/Sources/libevent-2.0.22-stable/.libs/

CFLAGS:= -g -O0 -static -DIPV6_V6ONLY=27 -DNO_SYS_UN=1 \
	-Ilibevhtp  -I libevhtp/compat/ \
	-levent -lws2_32 \
	$(addprefix -isystem , $(SYSINC)) \
	$(addprefix -L , $(SYSLIB)) 

sources:= evhtp_proxy.c evhtp_sock_relay.c connector.c libevhtp/evhtp.c libevhtp/htparse.c libevhtp/evhtp_numtoa.c 
objects:= $(sources:.c=.o)

.PHONY: all clean

all: evhtp_proxy

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
