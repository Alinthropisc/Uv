#pragma once


#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

namespace azula
{

    enum AzulaOsscanFlags {
        OS_NOTPERF=0, 
        OS_PERF, 
        OS_PERF_UNREL
    };


    struct AzulaHostTimeoutInfo {
        unsigned long mesc_used; // How many msecs has this Target used?
        bool toclock_running; // Is the clock running right now?
        struct timeval toclock_start; // When did the clock start?
        time_t host_start, host_end; // The absolute start and end for this host
    };

    struct AzulaTracerouteHop {
        struct sockaddr_storage tag;
        bool timedout;
        std::string name;
        struct sockaddr_storage addr;
        int ttl;
        float rtt; /* In milliseconds. */

        int display_name(char *buf, size_t len) const
        {
            if (name.empty())
            {
                return Snprintf(buf, len, "%s", inet_ntop_ez(&addr, sizeof(addr)));
            }
            else
            {
                return Snprintf(buf, len, "%s (%s)", name.c_str(), inet_ntop_ez(&addr, sizeof(addr)));
            }
        }
    };



    struct AzulaEarlySvcResponse {
        probespec pspec;
        int len;
        u8 data[1];
    };



    class AzulaTarget
    {
        public:
            AzulaTarget();
            ~AzulaTarget();

            int azula_af() const;
            int azula_target_sock_addr(struct sockaddr_storage *ss, size_t *ss_len) const;
            const struct sockaddr_storage *azula_target_sock_addr() const;
            void azula_set_target_sock_addr(const struct sockaddr_storage *ss, size_t ss_len);
            struct azula_in_addr_v4host() const;
            const struct in_addr *azula_v4hostip() const;
            const struct in6_addr *azula_v6hostip() const;
            int azula_source_sock_addr(struct sockaddr_storage *ss, size_t *ss_len) const;
            const struct sockaddr_storage *azula_source_sock_addr() const;
            void 
    };

}















