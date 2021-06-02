#ifndef DNS_CACHE_H
#define DNS_CACHE_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define fixline 909

struct pair {
    unsigned char addr[16];
    unsigned char hostname[50];
};

struct cache {
    struct pair *storage;
    int cacheSize;
};

//初始化cache
void initCache(struct cache * cache);

// //ip地址在cache找到
// int ipFoundInCache(struct cache * cache, unsigned char * ip);

//hostname在cache找到
int hostnameFoundInCache(struct cache * cache, unsigned char * hostname);

//根据hostname返回ip地址
unsigned char * getIpByHostname(struct cache * cache, unsigned char * hostname);

//关闭cache
void closeCache(struct cache * cache);

//打印cache
void printCache(struct cache * cache);


#endif