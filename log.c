#include "log.h"

#define DEFAULT_LOG_FILE stdout

LogPriority log_prio_base = LOG_LEVEL_DEBUG;
FILE *log_file = NULL;

void log_init(const char *filename, LogPriority prio)
{
    FILE *f = NULL;
    log_prio_base = prio;

    if (filename && (f = fopen(filename, "a"))) {
        log_file = f;
    } else {
        log_file = DEFAULT_LOG_FILE;
    }
}

void log_fini()
{
    if (log_file != DEFAULT_LOG_FILE) {
        fclose(log_file);
    }
}


