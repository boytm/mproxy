#ifndef __LOG_H__
#define __LOG_H__

#include <stdio.h>

#define __QUOTE(x)              # x
#define  _QUOTE(x)              __QUOTE(x)
#if _WIN32
# define DIRECTORY_SEPARATOR_CHAR '\\'
#else
# define DIRECTORY_SEPARATOR_CHAR '/'
#endif

#if _MSC_VER <= 1800 /* VC++ 2013 claim this, but still leads to C2065, so try VC++ 2015 */
# define __func__ __FUNCTION__
/* VC++ 2015 have C99 snprintf */
# define snprintf evutil_snprintf
#endif
#if _MSC_VER
# define inline __inline
#endif

#define __FILENAME__ (strrchr(__FILE__, DIRECTORY_SEPARATOR_CHAR) ? \
        strrchr(__FILE__, DIRECTORY_SEPARATOR_CHAR) + 1 : __FILE__)

#ifdef ANDROID
# include <android/log.h>

#define TAG "minivtun"

#define LOG(prio, fmt, ...)                                                \
        ((void)__android_log_print(prio, TAG, \
                                           __FILE__ ":[" _QUOTE(__LINE__) "]\t" fmt, ## __VA_ARGS__))

#define LOGD(...) LOG(ANDROID_LOG_DEBUG, __VA_ARGS__)
#define LOGI(...) LOG(ANDROID_LOG_INFO, __VA_ARGS__)
#define LOGW(...) LOG(ANDROID_LOG_WARN, __VA_ARGS__)
#define LOGE(...) LOG(ANDROID_LOG_ERROR, __VA_ARGS__)

#else
typedef enum LogPriority {
    LOG_LEVEL_VERBOSE,
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARN,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_FATAL,
} LogPriority;

extern LogPriority log_prio_base;
extern FILE *log_file;

static inline const char* PRIORITY_TO_STRING(LogPriority prio)
{
#define case_statement(x) case LOG_LEVEL_ ## x: return (#x);

    switch(prio)
    {
        case_statement(DEBUG);
        case_statement(INFO);
        case_statement(WARN);
        case_statement(ERROR);
        case_statement(FATAL);
        default:
        return ("UNKOWN");
    }

#undef case_statement
}

#ifdef _MSC_VER
/* The Visual C++ implementation will suppress a trailing comma if no arguments are passed to the ellipsis. */
#define LOG(prio, fmt, ...) do {                                                               \
    if (prio >= log_prio_base) {                                                                   \
            time_t      t  = time(NULL);                                                               \
            struct tm dm; localtime_s(&dm, &t);                                                        \
                                                                                                       \
            fprintf(log_file, "[%02d:%02d:%02d] %s %s:[" _QUOTE(__LINE__) "]: " \
                                    fmt "\n", dm.tm_hour, dm.tm_min, dm.tm_sec, PRIORITY_TO_STRING(prio), __FILENAME__, ## __VA_ARGS__);          \
            fflush(log_file);                                                                            \
            }                                                                                                     \
} while (0)
#else
#define LOG(prio, fmt, ...) do {                                                               \
    if (prio >= log_prio_base) {                                                                   \
            time_t      t  = time(NULL);                                                               \
            struct tm * dm = localtime(&t);                                                            \
                                                                                                       \
            fprintf(log_file, "[%02d:%02d:%02d] %s %s:[" _QUOTE(__LINE__) "]: " \
                                    fmt "\n", dm->tm_hour, dm->tm_min, dm->tm_sec, PRIORITY_TO_STRING(prio), __FILENAME__, ## __VA_ARGS__);          \
            fflush(log_file);                                                                            \
    }                                                                                                  \
} while (0)
#endif

#ifdef _MSC_VER
#define LOGD(fmt, ...) LOG(LOG_LEVEL_DEBUG, fmt, ## __VA_ARGS__)
#define LOGI(fmt, ...) LOG(LOG_LEVEL_INFO, fmt, ## __VA_ARGS__)
#define LOGW(fmt, ...) LOG(LOG_LEVEL_WARN, fmt, ## __VA_ARGS__)
#define LOGE(fmt, ...) LOG(LOG_LEVEL_ERROR, fmt, ## __VA_ARGS__)
#else
#define LOGD(fmt, ...) LOG(LOG_LEVEL_DEBUG, fmt, ## __VA_ARGS__)
#define LOGI(fmt, ...) LOG(LOG_LEVEL_INFO, fmt, ## __VA_ARGS__)
#define LOGW(fmt, ...) LOG(LOG_LEVEL_WARN, fmt, ## __VA_ARGS__)
#define LOGE(fmt, ...) LOG(LOG_LEVEL_ERROR, fmt, ## __VA_ARGS__)
#endif

void log_init(const char *filename, LogPriority prio);
void log_fini();

#endif

#endif
