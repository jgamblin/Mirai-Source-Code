#pragma once

#include "includes.h"

#define BINARY_BYTES_PER_ECHOLINE   128

struct binary {
    char arch[6];
    int hex_payloads_len;
    char **hex_payloads;
};

BOOL binary_init(void);
struct binary *binary_get_by_arch(char *arch);

static BOOL load(struct binary *bin, char *fname);
