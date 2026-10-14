#include "libuvb.h"

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
#if HAVE_NETDB_H
#include <netdb.h>
#endif
#include <assert.h>


#if !defined(HAVE_GAI_STRERROR) || defined(__MINGW32__)
#ifdef __MINGW32__
#undef gai_strerror
#endif

const char *gai_strerror(int errcode)
{
    static char customerr[64];

    switch (errcode)
    {
        case EAI_FAMILY:
            return "ai_family not supported";
        case EAI_NODATA:
            return "no address associated with hostname";
        case EAI_NONAME:
            return "hostname nor servname provided, or not known";
        default:
            Snprintf(customerr, sizeof(customerr), "unknown error (%d)", errcode);
            return "unknown error.";
    }
    return NULL; /* unreached */
}
#endif

#ifdef __MINGW32__
char* WSAAPI gai_strerrorA (int errcode)
{
  return gai_strerror(errcode);
}
#endif

#ifndef HAVE_GETADDRINFO
void freeaddrinfo(struct addrinfo *res)
{
    struct addrinfo *next;

    do {
        next = res->ai_next;
        free(res);
    } while ((res = next) != NULL);
}

/* Allocates and initializes a new AI structure with the port and IPv4
   address specified in network byte order */
static struct addrinfo *new_ai(unsigned short portno, u32 addr)
{
    struct addrinfo *ai;
    ai = (struct addrinfo *) safe_malloc(sizeof(struct addrinfo) + sizeof(struct sockaddr_in));
    memset(ai, 0, sizeof(struct addrinfo) + sizeof(struct sockaddr_in));
    ai->ai_family = AF_INET;
    ai->ai_addrlen = sizeof(struct sockaddr_in);
    ai->ai_addr = (struct sockaddr *)(ai + 1);
    ai->ai_addr->sa_family = AF_INET;
#if HAVE_SOCKADDR_SA_LEN
    ai->ai_addr->sa_len = ai->ai_addrlen;
#endif
    ((struct sockaddr_in *)(ai)->ai_addr)->sin_port = portno;
    ((struct sockaddr_in *)(ai)->ai_addr)->sin_addr.s_addr = addr;
    return(ai);
}


int getaddrinfo(const char *node, const char *service,const struct addrinfo *hints, struct addrinfo **res)
{

    struct addrinfo *cur, *prev = NULL;
    struct hostent *he;
    struct in_addr ip;
    unsigned short portno;
    int i;

    if (service)
    {
        portno = htons(atoi(service));
    }
    else
    {
        portno = 0;
    }

    if (hints && hints->ai_flags & AI_PASSIVE)
    {
        *res = new_ai(portno, htonl(0x00000000));
        return 0;
    }

    if (!node)
    {
        *res = new_ai(portno, htonl(0x7f000001));
        return 0;
    }

    if (inet_pton(AF_INET, node, &ip))
    {
        *res = new_ai(portno, ip.s_addr);
        return 0;
    }
    he = gethostbyname(node);

    if (he && he->h_addr_list[0])
    {
        for (i = 0; he->h_addr_list[i]; i++)
        {
            cur = new_ai(portno, ((struct in_addr *)he->h_addr_list[i])->s_addr);

            if (prev)
            {
                prev->ai_next = cur;
            }
            else
            {
                *res = cur;
            }

            prev = cur;
        }
        return 0;
    }
    return EAI_NODATA;
}
#endif /* HAVE_GETADDRINFO */