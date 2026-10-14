#include <stdio.h>

#include "libuvb.h"


NORETURN static void fatal(char *fmt, ...)__attribute__ ((format (printf, 1, 2)));

static void fatal(char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fflush(stdout);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\nQUITTING!\n");
    va_end(ap);
    exit(1);
}

void *safe_malloc(size_t size)
{
    void *mymem;

    if ((int)size < 0)            /* Catch caller errors */
    {
        fatal("Tried to malloc negative amount of memory!!!");
    }
    mymem = malloc(size);

    if (mymem == NULL)
    {
        fatal("Malloc Failed! Probably out of space.");
    }
    return mymem;
}

void *safe_realloc(void *ptr, size_t size)
{
    void *mymem;

    if ((int)size < 0)            /* Catch caller errors */
    {
        fatal("Tried to realloc negative amount of memory!!!");
    }
    mymem = realloc(ptr, size);

    if (mymem == NULL)
    {
        fatal("Realloc Failed! Probably out of space.");
    }
    return mymem;
}

/* Zero-initializing version of safe_malloc */
void *safe_zalloc(size_t size)
{
    void *mymem;

    if ((int)size < 0)
    {
        fatal("Tried to malloc negative amount of memory!!!");
    }
    mymem = calloc(1, size);

    if (mymem == NULL)
    {
        fatal("Malloc Failed! Probably out of space.");
    }
    return mymem;
}