
from SCons.Defaults import processDefines

def config_h_build(target, source, env):
    config_h_defines = { }
    for define in processDefines(env["CPPDEFINES"]):
        l = define.split("=", 1)
        if len(l) == 2:
            config_h_defines[l[0]] = l[1]
        else:
            config_h_defines[l[0]] = ""

    #print config_h_defines
    for a_target, a_source in zip(target, source):
        with open(str(a_target), "w") as config_h:
            with open(str(a_source), "r") as f:
                for line in f:
                    if line.startswith("#cmakedefine "):
                        _, key = line.split(None, 1)
                        key = key.strip()
                        if key in config_h_defines:
                            config_h.write("#define %s %s\n" % (key, config_h_defines[key]))
                        else:
                            config_h.write("#undef %s\n" % key)
                    else:
                        config_h.write("%s" % line)

#env = Environment(CCFLAGS = '-g -O0 -Wall')
env = Environment(CCFLAGS = '-g -O2 -Wall')
#env['CPPDEFINES'] = ['EVHTP_DEBUG=1']
#env['CPPFLAGS'] = 
#env['CPPPATH'] = []
#env['LIBPATH'] = []
#env['LIBS'] = []
env['EVHTP_DIR'] = 'libevhtp'
libs = ['pthread', 'rt']

if not env.GetOption('clean'):
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
        conf.env.Append(CPPDEFINES = ['NO_STRNDUP'])
    if not conf.CheckFunc('strnlen'):
        conf.env.Append(CPPDEFINES = ['NO_STRNLEN'])
    if conf.CheckHeader('openssl/evp.h') and conf.CheckHeader('openssl/kdf.h'):
        conf.env.Append(CPPDEFINES = ['USE_CRYPTO_OPENSSL', 'ENABLE_SS'])
    if conf.CheckFunc('strerror_r'):
        conf.env.Append(CPPDEFINES = ['HAVE_STRERROR_R'])
    if conf.CheckFunc('splice'):
        conf.env.Append(CPPDEFINES = ['HAVE_SPLICE'])
    if not conf.CheckLib('event_openssl'):
        conf.env.Append(CPPDEFINES = ['EVHTP_DISABLE_SSL'])
        libs += ['event', 'crypto']
    else:
        libs += ['event', 'event_openssl', 'ssl', 'crypto', 'dl']
    
    conf.env.Append(CPPDEFINES = {"EVHTP_SYS_ARCH" : (8 * conf.CheckTypeSize("size_t"))})
    conf.env.Append(CPPDEFINES = ['EVHTP_DISABLE_REGEX', 'EVHTP_DISABLE_EVTHR'])
    env = conf.Finish()

if env['PLATFORM'] in ('win32', 'mingw'):
    env['LIBS'] += "ws2_32"

env.Decider('timestamp-match')

config_h_action = Action(config_h_build, varlist=['CPPDEFINES'])
env.Command('$EVHTP_DIR/evhtp-config.h', '$EVHTP_DIR/evhtp-config.h.in', config_h_action)
env.Append(CPPPATH = ['libevhtp', 'libevhtp/compat'])
libevhtp_srcs = Split('libevhtp/evhtp.c libevhtp/evhtp_numtoa.c libevhtp/evthr.c libevhtp/htparse.c')
libevhtp_objs = [env.Object(i) for i in libevhtp_srcs]


env.Program('evhtp_get', ['evhtp_get.c', ] + libevhtp_objs,
                LIBS = libs,
                LIBPATH = ['/usr/local/lib', '/usr/lib', ])

evhtp_proxy = env.Program('mproxy', Split('evhtp_proxy.c evhtp_sock_relay.c lru.c dns_forward.c connector.c http_connector.c ss_connector.c encrypt.c utils.c log.c') + libevhtp_objs,
		CCFLAGS = env['CCFLAGS'] + ' ',
                LIBS = libs,
                LIBPATH = ['/usr/local/lib', '/usr/lib', ])

env.Install('/usr/local/bin', evhtp_proxy)
env.Alias('install', '/usr/local/bin')

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
