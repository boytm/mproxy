#env = Environment(CCFLAGS = '-g -O0 -Wall')
env = Environment(CCFLAGS = '-g -O2 -Wall')
env['CPPPATH'] = []
env['LIBS'] = []
env['CPPDEFINES'] = {}

conf = Configure(env)
if not conf.CheckLibWithHeader('event', 'event2/event.h', 'c'):
	print 'libevent 2.12+ required!'
	Exit(1)

if not conf.CheckHeader('sys/un.h'):
    conf.env.Append(CPPDEFINES = "NO_SYS_UN")
if not conf.CheckFunc('strndup'):
    conf.env.Append(CPPDEFINES = 'NO_STRNDUP=1')
if not conf.CheckFunc('strnlen'):
    conf.env.Append(CPPDEFINES = 'NO_STRNLEN=1')

env.Append(CPPDEFINES={"EVHTP_SYS_ARCH" : (8 * conf.CheckTypeSize("size_t"))})
env = conf.Finish()

if env['PLATFORM'] in ('win32', 'mingw'):
    env['LIBS'] += "ws2_32"

print env['TOOLS']
print env['PLATFORM']

env.Decider('timestamp-match')

env['CPPPATH'] += ['libevhtp', ]
libevhtp_srcs = Split('libevhtp/evhtp.c libevhtp/evhtp_numtoa.c libevhtp/evthr.c libevhtp/htparse.c')
libevhtp_objs = [env.Object(i) for i in libevhtp_srcs]

env['EVHTP_DIR'] = 'libevhtp'
env.Command('$EVHTP_DIR/evhtp-config.h', 'evhtp-config.h.win32', 'cp $SOURCES $TARGET')

env.Program('evhtp_get', ['evhtp_get.c', ] + libevhtp_objs,
                CPPPATH = ['libevhtp', '/usr/include/mysql/'],
                LIBS = ['event', 'crypto', 'pthread', 'rt'],
                LIBPATH = ['/usr/local/lib', '/usr/lib', ])

evhtp_proxy = env.Program('mproxy', Split('evhtp_proxy.c evhtp_sock_relay.c connector.c ss_connector.c encrypt.c') + libevhtp_objs,
				CCFLAGS = env['CCFLAGS'] + ' -DUSE_CRYPTO_OPENSSL=1',
                CPPPATH = ['libevhtp', '/usr/include/mysql/'],
                LIBS = ['event', 'crypto', 'pthread', 'rt'],
                LIBPATH = ['/usr/local/lib', '/usr/lib', ])

env.Install('/usr/local/bin', evhtp_proxy)
env.Alias('install', '/usr/local/bin')

