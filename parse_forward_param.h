#pragma once
#include <stdint.h>
#include <stdlib.h>

#define INET6_ADDRSTRLEN 46

struct forwarder_param_t
{
    char bind_ip[INET6_ADDRSTRLEN];
    char forward_ip[INET6_ADDRSTRLEN];
    unsigned short bind_port;
    unsigned short forward_port;
};

int parse_forward_param(const char *str, size_t len, struct forwarder_param_t *param);

