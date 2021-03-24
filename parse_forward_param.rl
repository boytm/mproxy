#include "parse_forward_param.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if DEBUG
# define LOGE(fmt, ...) fprintf(stderr, fmt "\n", ## __VA_ARGS__)
# define LOGD LOGE
#else
# include "log.h"
#endif


%%{
    machine parse_forward_param;

    action char {;}
    action err_char { 
        LOGE("%*s", (int)len, str);
        LOGE("%*s", (int)(1 + p - str), "^");
        goto fail;
    }

    action init_bind_ip {bind_ip_start = p;}
    action finish_bind_ip {
        LOGD("bind ip %.*s", (int)(p - bind_ip_start), bind_ip_start);
        strncpy(param->bind_ip, bind_ip_start, p - bind_ip_start);
    }

    action init_bind_port {bind_port_start = p;}
    action finish_bind_port {
        LOGD("bind port %.*s", (int)(p - bind_port_start), bind_port_start);
        int port = atoi(bind_port_start);
        if (port <= 0 || port > 65535) {
            LOGE("invalid port range");
            goto fail;
        }
        param->bind_port = (unsigned short)port;
    }

    action init_forward_ip {forward_ip_start = p;}
    action finish_forward_ip {
        LOGD("forward ip %.*s", (int)(p - forward_ip_start), forward_ip_start);
        strncpy(param->forward_ip, forward_ip_start, p - forward_ip_start);
    }

    action init_forward_port {forward_port_start = p;}
    action finish_forward_port {
        LOGD("forward port %.*s", (int)(p - forward_port_start), forward_port_start);
        int port = atoi(forward_port_start);
        if (port <= 0 || port > 65535) {
            LOGE("invalid port range");
            goto fail;
        }
        param->forward_port = (unsigned short)port;
    }


    #alpha       = [a-zA-Z];
    #digit       = [0-9];
    hexdigit    = [0-9a-fA-F];
    unreserved  = alpha | digit | [\-._~];
    pct_encoded = "%" hexdigit{2};
    sub_delims  = [!$&'()*+,;=];
    pchar       = unreserved | pct_encoded | sub_delims | [:@];

    scheme = alpha (alpha | digit | [\-+.])*;
    userinfo = (unreserved | pct_encoded | sub_delims | ":")* ;
    dec_octet
        = digit
        | [\x31-\x39] digit
        | "1" digit{2}
        | "2" [\x30-\x34] digit
        | "25" [\x30-\x35];
    ipv4address = dec_octet "." dec_octet "." dec_octet "." dec_octet;
    h16         = hexdigit{1,4};
    ls32        = h16 ":" h16 | ipv4address;
    ipv6address
        =                            (h16 ":"){6} ls32
        |                       "::" (h16 ":"){5} ls32
        | (               h16)? "::" (h16 ":"){4} ls32
        | ((h16 ":"){0,1} h16)? "::" (h16 ":"){3} ls32
        | ((h16 ":"){0,2} h16)? "::" (h16 ":"){2} ls32
        | ((h16 ":"){0,3} h16)? "::"  h16 ":"     ls32
        | ((h16 ":"){0,4} h16)? "::"              ls32
        | ((h16 ":"){0,5} h16)? "::"              h16
        | ((h16 ":"){0,6} h16)? "::";
    ipvfuture   = "v" hexdigit+ "." (unreserved | sub_delims | ":" )+;
    ip_literal  = "[" ( ipv6address | ipvfuture ) "]";
    reg_name    = (unreserved | pct_encoded | sub_delims)*;
    ip          = ipv4address | ip_literal;
    host
        = ip_literal  
        | ipv4address 
        | reg_name    ;
    port        = digit{1,5} ;


    main := (
        (ip > init_bind_ip % finish_bind_ip ":")?
        port > init_bind_port % finish_bind_port ":"
        ip > init_forward_ip % finish_forward_ip ":"
        port > init_forward_port % finish_forward_port
    ) $! err_char;
}%%


%%{
write data;
}%%

/*  
 *  input format:
 *    [bind_ip]:bind_port:forward_ip:forward_port
 *  return: 0 success
 */
int parse_forward_param(const char *str, size_t len, struct forwarder_param_t *param)
{
    const char *bind_ip_start = NULL, *bind_port_start = NULL, *forward_ip_start = NULL, *forward_port_start = NULL;


    int cs = 0;
    const char *p = str;
    const char *pe = p + len;
    const char *eof = pe;

    %% write init;
    %% write exec;

    if(cs >= parse_forward_param_first_final)
    {
        if (param->bind_ip[0] == 0)
        {
            strcpy(param->bind_ip, "127.0.0.1");
        }

        LOGD("success %s:%hu --> %s:%hu\n", param->bind_ip, param->bind_port, param->forward_ip, param->forward_port);

        return 0;
    }
    LOGE("param is too short");

fail:
    if (param->bind_ip[0]) {
        param->bind_ip[0] = '\0';
    }
    if (param->forward_ip[0]) {
        param->forward_ip[0] = '\0';
    }

    return -1;
}


#if DEBUG
int main(int argc, char **argv)
{
    for(int idx = 1; idx < argc; ++idx)
    {
        struct forwarder_param_t param = {0};
        LOGD("\nparse: %s\n", argv[idx]);
        parse_forward_param(argv[idx], strlen(argv[idx]), &param);
    }

    return 0;
}
#endif
