#include "utils.h"

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef _WIN32
# include <fcntl.h>
# include <sys/types.h>
# include <sys/stat.h>
# include <pwd.h>
# include <grp.h>
# include <unistd.h>
#endif

#ifndef _WIN32
int write_pid_file(const char *pid_file)
{
    int pidfd = -1;
    char pidstr[100] = {0};
    int ret = 1;
    ssize_t len;

    unlink(pid_file);
    pidfd = open(pid_file, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (pidfd < 0) {
        LOGE("Open pid file failed: %s", strerror(errno));
        goto out;
    }
    snprintf(pidstr, sizeof(pidstr), "%d\n", getpid());
    len = write(pidfd, pidstr, strlen(pidstr));
    if (len == -1) {
        LOGE("Write pid file failed: %s", strerror(errno));
        goto out;
    }
    ret = 0; // success

out:
    if (pidfd >= 0) close(pidfd);
    return ret;
}

/*
 * getpwnam() and getgrnam() is MT-Unsafe
 * return 0 on success
 */
int change_user(const char *userspec)
{
    char buf[4096] = { '\0' };
    struct passwd *pw = NULL;
    struct group *gr = NULL;
    gid_t gid;
    uid_t uid;
    int saved;
    int ret = 1;

    saved = errno;
    strncpy(buf, userspec, sizeof(buf) / sizeof(buf[0]) - 1);

    const char *user_name = buf;
    const char *group_name = NULL;
    char *pos = strchr(buf, ':');

    if (pos) {
        *pos = '\0';
        group_name = pos + 1;
    }

    errno = 0;
    if (NULL == (pw = getpwnam(user_name))) {
        LOGE("Cannot find user '%s': %s", user_name, (errno ? strerror(errno) : ""));
        goto out;
    } else {
        uid = pw->pw_uid;
        gid = pw->pw_gid;
    }

    if (group_name && group_name[0]) {
        errno = 0;
        if (NULL == (gr = getgrnam(group_name))) {
            LOGE("Cannot find group '%s': %s", group_name, (errno ? strerror(errno) : ""));
            goto out;
        } else {
            gid = gr->gr_gid;
        }
    }

    if (0 != setgid(gid)) {
        LOGE("Set group ID failed %u: %s", (unsigned)gid, strerror(errno));
        goto out;
    }
    if (0 != setuid(uid)) {
        LOGE("Set user ID failed %u: %s", (unsigned)uid, strerror(errno));
        goto out;
    }

    ret = 0; // success

out:
    errno = saved;
    return ret;
}
#endif // !_WIN32

void hexdump(FILE *out, const void *p, int len)
{
    const unsigned char *line;
    int i;
    int thisline;
    int offset;

    line = (const unsigned char *)p;
    offset = 0;

    while (offset < len) {
        fprintf(out, "%04x ", offset);
        thisline = len - offset;

        if (thisline > 16) {
            thisline = 16;
        }

        for (i = 0; i < thisline; i++) {
            fprintf(out, "%02x ", line[i]);
        }

        for (; i < 16; i++) {
            fprintf(out, "   ");
        }

        for (i = 0; i < thisline; i++) {
            fprintf(out, "%c", (line[i] >= 0x20 && line[i] < 0x7f) ? line[i] : '.');
        }

        fprintf(out, "\n");
        offset += thisline;
        line += thisline;
    }
}

static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

char *base64_encode(const unsigned char *src, size_t len)
{
    unsigned char *out, *pos;
    const unsigned char *end, *in;
    size_t olen;

    olen = len * 4 / 3 + 4; /* 3-byte blocks to 4-byte */
    out = malloc(olen);
    if (out == NULL)
        return NULL;

    end = src + len;
    in = src;
    pos = out;
    while (end - in >= 3) {
        *pos++ = base64_chars[in[0] >> 2];
        *pos++ = base64_chars[((in[0] & 0x03) << 4) | (in[1] >> 4)];
        *pos++ = base64_chars[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
        *pos++ = base64_chars[in[2] & 0x3f];
        in += 3;
    }

    if (end - in > 0) {
        *pos++ = base64_chars[in[0] >> 2];
        if (end - in == 1) {
            *pos++ = base64_chars[(in[0] & 0x03) << 4];
            *pos++ = '=';
        } else {
            *pos++ = base64_chars[((in[0] & 0x03) << 4) | (in[1] >> 4)];
            *pos++ = base64_chars[(in[1] & 0x0f) << 2];
        }
        *pos++ = '=';
    }

    *pos = '\0';
    return (char *)out;
}
