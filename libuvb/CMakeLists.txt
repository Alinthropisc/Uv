cmake_minimum_required(VERSION 4.2)
project(libuvb C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED OFF)
set(CMAKE_C_STANDARD_DEFAULT ON)


add_library(libuvb STATIC library.c
        libuvb.h
        libuvb.h
        libuvb_ipv6.h
        libuvb_winunix.c
        libuvb_winunix.h
        libuvb_winconfig.h
        libuvb_time.c
        libuvb_str.c
        libuvb_rnd.c
        libuvb_misc.c
        libuvb_memalloc.c
        libuvb_crc32ct.h
        libuvb_addrset.c
        inet_pton.c
        inet_ntop.c
        getopt.c
        getopt.h
        getnameinfo.c
        getaddrinfo.c)
