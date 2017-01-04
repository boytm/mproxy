#ifndef __UTILS_H__
#define __UTILS_H__

#include <stdio.h>
#include <time.h>
#include "log.h"

#ifndef _WIN32
int write_pid_file(const char *pid_file);
int change_user(const char *userspec);
#endif
void hexdump(FILE *out, const void *p, int len);

#endif // __UTILS_H__
