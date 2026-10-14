#include "libuvb.h"

#if HAVE_NETDB_H
#include <netdb.h>
#endif
#include <assert.h>
#include <stdio.h>
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

int getnameinfo(const struct sockaddr *sa, size_t salen,char *host, size_t hostlen,char *serv, size_t servlen, int flags)
{

    struct sockaddr_in *sin = (struct sockaddr_in *)sa;
    struct hostent *he;

    if (sin->sin_family != AF_INET || salen != sizeof(struct sockaddr_in))
    {
        return EAI_FAMILY;
    }

    if (serv != NULL)
    {
        Snprintf(serv, servlen, "%d", ntohs(sin->sin_port));
        return 0;
    }

    if (host)
    {
        if (flags & NI_NUMERICHOST)
        {
            Strncpy(host, inet_ntoa(sin->sin_addr), hostlen);
            return 0;
        }
        else
        {
            he = gethostbyaddr((char *)&sin->sin_addr, sizeof(struct in_addr),AF_INET);

            if (he == NULL)
            {
                if (flags & NI_NAMEREQD)
                {
                    return EAI_NONAME;
                }
                Strncpy(host, inet_ntoa(sin->sin_addr), hostlen);
                return 0;
            }

            assert(he->h_name);
            Strncpy(host, he->h_name, hostlen);
            return 0;
        }
    }
    return 0;
}



