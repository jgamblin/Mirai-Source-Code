#pragma once

#include <stdint.h>
#include <linux/ip.h>

#include "includes.h"

uint16_t checksum_generic(uint16_t *, uint32_t);
uint16_t checksum_tcpudp(struct iphdr *, void *, uint16_t, int);
