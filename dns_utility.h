#ifndef DNS_TYPE_H
#define DNS_TYPE_H

#include <string.h>
#include <winsock2.h>

#define HEADER_LEN 12
struct header {
    unsigned short id;
    unsigned short flags;
    unsigned short qd_count;
    unsigned short an_count;
    unsigned short ns_count;
    unsigned short ar_count;
};

struct query {
    unsigned char hostname[256];
    unsigned short qtype;
    unsigned short qclass;
};

struct idAddrPair {
    unsigned short id;
    SOCKADDR_IN backAddr;
};

//判断是否为请求报文
int isRequest(char *recvBuf);

//解析query 部分
struct query parseQuery(char *recvBuf);

//判断请求的类型是否为A类
int isTypeA(struct query q);

#endif