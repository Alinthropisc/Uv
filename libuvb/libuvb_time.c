
#include "libuvb.h"

#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <time.h>
#ifdef WIN32
#include <sys/timeb.h>
#include <winsock2.h>
#endif

#ifndef HAVE_USLEEP
int usleep(unsigned long usec)
{
#ifdef HAVE_NANOSLEEP
    struct timespec ts;
ts.tv_sec = usec / 1000000;
ts.tv_nsec = (usec % 1000000) * 1000;
return nanosleep(&ts, NULL);
#else /* Windows style */
    Sleep( usec / 1000 );
    return 0;
#endif /* HAVE_NANOSLEEP */
}
#endif

/* Thread safe time stuff */
#ifdef WIN32
/* On Windows, use CRT function localtime_s:
 * errno_t localtime_s(
 *    struct tm* const tmDest,
 *       time_t const* const sourceTime
 *       );
 */
int n_localtime(const time_t *timer, struct tm *result)
{
  return localtime_s(result, timer);
}

int n_gmtime(const time_t *timer, struct tm *result)
{
  return gmtime_s(result, timer);
}

int n_ctime(char *buffer, size_t bufsz, const time_t *timer)
{
  return ctime_s(buffer, bufsz, timer);
}

#else // WIN32

#include <errno.h>
#ifdef HAVE_LOCALTIME_S
// C11 localtime_s similar to Posix localtime_r, but with validity checking:
// struct tm *localtime_s(const time_t *restrict time, struct tm *restrict result);
int n_localtime(const time_t *timer, struct tm *result)
{
  struct tm *tmp = localtime_s(timer, result);

  if (!tmp)
  {
    return errno;
  }
  return 0;
}

int n_gmtime(const time_t *timer, struct tm *result)
{
  struct tm *tmp = gmtime_s(timer, result);

  if (!tmp)
  {
    return errno;
  }
  return 0;
}

int n_ctime(char *buffer, size_t bufsz, const time_t *timer)
{
  return ctime_s(buffer, bufsz, timer);
}
#else
#ifdef HAVE_LOCALTIME_R
/* POSIX localtime_r thread-safe localtime function:
 * struct tm *localtime_r(const time_t *timep, struct tm *result);
 */
int n_localtime(const time_t *timer, struct tm *result)
{
  struct tm *tmp = localtime_r(timer, result);

  if (!tmp)
  {
    return errno;
  }
  return 0;
}

int n_gmtime(const time_t *timer, struct tm *result)
{
  struct tm *tmp = gmtime_r(timer, result);

  if (!tmp)
  {
    return errno;
  }
  return 0;
}

int n_ctime(char *buffer, size_t bufsz, const time_t *timer)
{
  char *tmp = ctime_r(timer, buffer);

  if (!tmp)
  {
    return errno;
  }
  return 0;
}

#else
/* No thread-safe alternatives. */
// Using C99's one-line commments since LGTM.com does not recognize C-style
// block comments. This may cause problems, but only for very old systems
// without a C99-compatible compiler that do not have localtime_r or
// localtime_s
int n_localtime(const time_t *timer, struct tm *result)
{
    struct tm *tmp = localtime(timer); // lgtm[cpp/potentially-dangerous-function]

    if (tmp)
    {
        *result = *tmp;
    }
    else
    {
        return errno;
    }
    return 0;
}

int n_gmtime(const time_t *timer, struct tm *result)
{
    struct tm *tmp = gmtime(timer); // lgtm[cpp/potentially-dangerous-function]

    if (tmp)
    {
        *result = *tmp;
    }
    else
    {
        return errno;
    }
    return 0;
}

int n_ctime(char *buffer, size_t bufsz, const time_t *timer)
{
    char *tmp = ctime(timer); // lgtm[cpp/potentially-dangerous-function]

    if (tmp)
    {
        Strncpy(buffer, tmp, bufsz);
    }
    else
    {
        return errno;
    }
    return 0;
}
#endif // HAVE_LOCALTIME_R
#endif // HAVE_LOCALTIME_S
#endif // WIN32

#ifdef WIN32
int gettimeofday(struct timeval *tv, struct timeval *tz)
{
  struct _timeb timebuffer;
  _ftime( &timebuffer );
  tv->tv_sec = (long) timebuffer.time;
  tv->tv_usec = timebuffer.millitm * 1000;
  return 0;
};

unsigned int sleep(unsigned int seconds)
{
  Sleep(1000*seconds);
  return(0);
};
#endif // WIN32