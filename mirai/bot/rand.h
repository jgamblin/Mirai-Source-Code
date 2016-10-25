#pragma once

#include <stdint.h>

#define PHI 0x9e3779b9

void rand_init(void);
uint32_t rand_next(void);
void rand_str(char *, int);
void rand_alphastr(uint8_t *, int);
