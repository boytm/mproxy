#env = Environment(CCFLAGS = '-g -O0 -Wall')
env = Environment(CCFLAGS = '-g -O2 -Wall')
env['CPPPATH'] = []
env['LIBS'] = []
env['CPPDEFINES'] = {}
env['EVHTP_DIR'] = 'libevhtp'
libs = ['pthread', 'rt']

conf = Configure(env)
if not conf.CheckLibWithHeader('event', 'event2/event.h', 'c'):
	print 'libevent 2.12+ required!'
	Exit(1)

if not conf.CheckHeader('sys/un.h'):
    conf.env.Append(CPPDEFINES = "NO_SYS_UN")
if not conf.CheckHeader('sys/queue.h'):
	env.Command('$EVHTP_DIR/compat/sys/queue.h', '$EVHTP_DIR/compat/sys/queue.h.in', 'cp $SOURCES $TARGET')
if not conf.CheckHeader('sys/tree.h'):
	env.Command('$EVHTP_DIR/compat/sys/tree.h', '$EVHTP_DIR/compat/sys/tree.h.in', 'cp $SOURCES $TARGET')
if not conf.CheckFunc('strndup'):
    conf.env.Append(CPPDEFINES = 'NO_STRNDUP=1')
if not conf.CheckFunc('strnlen'):
    conf.env.Append(CPPDEFINES = 'NO_STRNLEN=1')
if conf.CheckHeader('openssl/evp.h'):
    conf.env.Append(CPPDEFINES = ['USE_CRYPTO_OPENSSL=1', 'ENABLE_SS=1'])
if conf.CheckFunc('splice'):
    conf.env.Append(CPPDEFINES = 'HAVE_SPLICE=1')
if not conf.CheckLib('event_openssl'):
    conf.env.Append(CPPDEFINES = 'EVHTP_DISABLE_SSL=1')
    libs += ['event', 'crypto']
else:
    libs += ['event', 'event_openssl', 'ssl', 'crypto']

env.Append(CPPDEFINES={"EVHTP_SYS_ARCH" : (8 * conf.CheckTypeSize("size_t"))})
env = conf.Finish()

if env['PLATFORM'] in ('win32', 'mingw'):
    env['LIBS'] += "ws2_32"

env.Decider('timestamp-match')

env.Command('$EVHTP_DIR/evhtp-config.h', 'evhtp-config.h.win32', 'cp $SOURCES $TARGET')
env.Append(CPPPATH = ['libevhtp', 'libevhtp/compat'])
libevhtp_srcs = Split('libevhtp/evhtp.c libevhtp/evhtp_numtoa.c libevhtp/evthr.c libevhtp/htparse.c')
libevhtp_objs = [env.Object(i) for i in libevhtp_srcs]


env.Program('evhtp_get', ['evhtp_get.c', ] + libevhtp_objs,
                LIBS = libs,
                LIBPATH = ['/usr/local/lib', '/usr/lib', ])

evhtp_proxy = env.Program('mproxy', Split('evhtp_proxy.c evhtp_sock_relay.c lru.c connector.c ss_connector.c encrypt.c utils.c log.c') + libevhtp_objs,
		CCFLAGS = env['CCFLAGS'] + ' ',
                LIBS = libs,
                LIBPATH = ['/usr/local/lib', '/usr/lib', ])

env.Install('/usr/local/bin', evhtp_proxy)
env.Alias('install', '/usr/local/bin')

