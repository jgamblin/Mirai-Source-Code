#pragma once

#include "includes.h"

int util_strlen(char *);
BOOL util_strncmp(char *, char *, int);
BOOL util_strcmp(char *, char *);
int util_strcpy(char *, char *);
void util_memcpy(void *, void *, int);
void util_zero(void *, int);
int util_atoi(char *, int);
char *util_itoa(int, int, char *);
int util_memsearch(char *, int, char *, int);
int util_stristr(char *, int, char *);
ipv4_t util_local_addr(void);
char *util_fdgets(char *, int, int);

static inline int util_isupper(char);
static inline int util_isalpha(char);
static inline int util_isspace(char);
static inline int util_isdigit(char);

