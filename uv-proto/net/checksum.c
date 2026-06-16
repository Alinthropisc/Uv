// net/checksum.c — Internet checksum
// Derived from masscan util-checksum by Robert David Graham (MIT License)
// Adapted to C23 for uv project

#include "checksum.h"

uint32_t checksum_calculate(const void *vbuf, size_t length)
{
    const uint8_t *buf = vbuf;
    uint32_t sum = 0;
    size_t i;

    // Sum 16-bit words
    for (i = 0; i + 1 < length; i += 2)
        sum += (uint32_t)buf[i] << 8 | buf[i + 1];

    // Odd trailing byte (pad with zero)
    if (length & 1)
        sum += (uint32_t)buf[length - 1] << 8;

    return sum;
}

uint16_t checksum_finish(uint32_t sum)
{
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum = (sum >> 16) + (sum & 0xFFFF);
    return (uint16_t)(~sum & 0xFFFF);
}

uint16_t checksum_ipv4(uint32_t src, uint32_t dst,
                       uint8_t proto, size_t plen,
                       const void *payload)
{
    uint32_t sum = 0;
    sum += (src  >> 16) & 0xFFFF;
    sum += (src  >>  0) & 0xFFFF;
    sum += (dst  >> 16) & 0xFFFF;
    sum += (dst  >>  0) & 0xFFFF;
    sum += proto;
    sum += (uint32_t)plen;
    sum += checksum_calculate(payload, plen);

    // Zero out the checksum field inside the payload before finishing.
    // For TCP the checksum is at offset 16, UDP at 6, ICMP at 2.
    const uint8_t *p = payload;
    switch (proto) {
        case  1: sum -= (uint32_t)p[2] << 8 | p[3]; break; // ICMP
        case  6: sum -= (uint32_t)p[16] << 8 | p[17]; break; // TCP
        case 17: sum -= (uint32_t)p[6]  << 8 | p[7];  break; // UDP
        default: break;
    }

    return checksum_finish(sum);
}

uint16_t checksum_ipv6(const uint8_t src[16], const uint8_t dst[16],
                       uint8_t proto, size_t plen,
                       const void *payload)
{
    uint32_t sum = 0;
    sum += checksum_calculate(src, 16);
    sum += checksum_calculate(dst, 16);
    sum += (uint32_t)plen;
    sum += proto;
    sum += checksum_calculate(payload, plen);

    const uint8_t *p = payload;
    switch (proto) {
        case  1:
        case 58: sum -= (uint32_t)p[2] << 8 | p[3]; break; // ICMPv6
        case  6: sum -= (uint32_t)p[16] << 8 | p[17]; break;
        case 17: sum -= (uint32_t)p[6]  << 8 | p[7];  break;
        default: break;
    }

    return checksum_finish(sum);
}
