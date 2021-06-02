#include "dns_cache.h"

void initCache(struct cache * cache) {
    FILE* fp = fopen("./dnsrelay.txt", "r");
    
    cache->cacheSize = 0;
    cache->storage = malloc(sizeof(struct pair) * 2000);
    for(int i = 0; fscanf(fp, "%s", cache->storage[i].addr) != EOF; i++) {
        fscanf(fp, "%s", cache->storage[i].hostname);
        cache->cacheSize++;
    }
}

void closeCache(struct cache * cache) {
    free(cache->storage);
}

int ipFoundInCache(struct cache * cache, unsigned char * ip) {
    for(int i = 0; i < cache->cacheSize; i++) {
        if(strcmp(cache->storage[i].addr, ip) == 0) {
            return 1;
        }
    }
    return 0;
}

int hostnameFoundInCache(struct cache * cache, unsigned char * hostname) {
    for(int i = 0; i < cache->cacheSize; i++) {
        if(strcmp(cache->storage[i].hostname, hostname) == 0) {
            return 1;
        }
    }
    return 0;
}

//根据hostname返回ip地址
unsigned char * getIpByHostname(struct cache * cache, unsigned char * hostname) {
    for(int i = 0; i < cache->cacheSize; i++) {
        if(strcmp(cache->storage[i].hostname, hostname) == 0) {
            return cache->storage[i].hostname;
        }
    }
}


void printCache(struct cache * cache) {
    printf("cache size is %d\n", cache->cacheSize);
    for(int i = 0;i < cache->cacheSize; i++) {
        printf("%s %s\n", cache->storage[i].addr, cache->storage[i].hostname);
    }
}