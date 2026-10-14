#pragma once



#if HAVE_CONFIG_H
#include "libuvb_config.h"
#else
#ifdef WIN32
#include "libuvb_winconfig.h"
#endif /* WIN32 */
#endif /* HAVE_CONFIG_H */

#ifdef __cplusplus
extern "C" {
#endif

/* reset argument parser to start-up values */
extern int getopt_reset(void);

#ifndef HAVE_GETOPT
/* UNIX-style short-argument parser */
extern int getopt(int argc, char * argv[], const char *opts);
#endif /* HAVE_GETOPT */

extern int optind, opterr, optopt;
extern char *optarg;

struct option {
    const char *name;
    int has_arg;
    int *flag;
    int val;
};

/* human-readable values for has_arg */
#undef no_argument
#define no_argument 0
#undef required_argument
#define required_argument 1
#undef optional_argument
#define optional_argument 2

/* GNU-style long-argument parsers */
extern int getopt_long(int argc, char * argv[], const char *shortopts,const struct option *longopts, int *longind);

extern int getopt_long_only(int argc, char * argv[], const char *shortopts,const struct option *longopts, int *longind);

extern int _getopt_internal(int argc, char * argv[], const char *shortopts,const struct option *longopts, int *longind,int long_only);

#ifdef __cplusplus
}
#endif






























