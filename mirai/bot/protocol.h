#pragma once

#include <stdint.h>

#include "includes.h"

struct dnshdr {
    uint16_t id, opts, qdcount, ancount, nscount, arcount;
};

struct dns_question {
    uint16_t qtype, qclass;
};

struct dns_resource {
    uint16_t type, _class;
    uint32_t ttl;
    uint16_t data_len;
} __attribute__((packed));

struct grehdr {
    uint16_t opts, protocol;
};

#define PROTO_DNS_QTYPE_A       1
#define PROTO_DNS_QCLASS_IP     1

#define PROTO_TCP_OPT_NOP   1
#define PROTO_TCP_OPT_MSS   2
#define PROTO_TCP_OPT_WSS   3
#define PROTO_TCP_OPT_SACK  4
#define PROTO_TCP_OPT_TSVAL 8

#define PROTO_GRE_TRANS_ETH 0x6558
