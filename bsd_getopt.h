/* bsd_getopt.h
 *
 * Chris Collins <chris@collins.id.au>
 */

/** header created for NetBSD getopt/getopt_long */

#ifndef HAVE_GETOPT_LONG
#ifndef _BSD_GETOPT_H
#define _BSD_GETOPT_H

#ifdef WIN32
#include <tchar.h>
#else
#define TCHAR char
#endif

#ifdef __cplusplus
extern "C" {
#endif

extern int    opterr; /* prevent the error message by setting opterr to 0 */
extern int    optind;
extern int    optopt;
extern int    optreset;
extern TCHAR  *optarg;

struct option {
    TCHAR  *name;
    int    has_arg;
    int   *flag;
    int    val;
};

#define no_argument        0
#define required_argument  1
#define optional_argument  2

extern int getopt(int nargc, TCHAR * const *nargv, const TCHAR *options);
extern int getopt_long(int nargc, TCHAR * const *nargv, const TCHAR *options, const struct option *long_options, int *idx);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _BSD_GETOPT_H */
#endif
