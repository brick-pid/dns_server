#include "dns_utility.h"

// 判断DNS是请求报文还是回答报文
int isRequest(char *buffer)
{
    // Flag中的Response字段，一位
    // 0为查询报文, query
    if(((buffer[2]>>7)&0x01)==0)
    {
        return 1;
    }
    // 1为响应报文, response
    return 0;
}

//解析query 部分
struct query parseQuery(char *recvBuf)
{
    int i;
    struct query res;
    memset(res.hostname, 0, 256);
    // 解析Name
    for(i = HEADER_LEN; recvBuf[i]!=0x00; i++)
    {
        strncat(res.hostname, recvBuf + i + 1, recvBuf[i]);
        strcat(res.hostname, ".");
        i = i + recvBuf[i];
    }
    // 解析Type
    res.qtype = ((recvBuf[i+1] << 8) + recvBuf[i+2])&0xffff;
    // 解析Class
    res.qclass = ((recvBuf[i+3] << 8) + recvBuf[i+4])&0xffff;
    return res;
}

//判断请求的类型是否为A类
int isTypeA(struct query q) {
    return q.qtype == 1;
}