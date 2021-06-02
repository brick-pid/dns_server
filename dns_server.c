#include <winsock2.h>
#include <stdio.h>
#include "dns_utility.h"
#include "dns_cache.h"

#define PORT 53
#define LOCAL_ADDRESS "127.0.0.1"
#define DNS_SERVER_ADDRESS "4.2.2.2"

void printIp(struct in_addr sin_addr) {
    printf("ip: %d %d %d %d \n", sin_addr.S_un.S_un_b.s_b1, \
        sin_addr.S_un.S_un_b.s_b2, sin_addr.S_un.S_un_b.s_b3, sin_addr.S_un.S_un_b.s_b4);
}

int main(int argc, char *argv[]) {

    int iResult = 0;
    //------------------------
    // 初始化 Winsock 库
    WSADATA wsaData;
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != NO_ERROR) {
        wprintf(L"WSAStartup failed with error %d\n", iResult);
        return 1;
    }

    //------------------------------------------------
    //创建 socket 
    SOCKET localSock = socket(AF_INET, SOCK_DGRAM, 0);
    SOCKET localSockOut = socket(AF_INET, SOCK_DGRAM, 0);

    //将发给上层服务器的socket设置为非阻塞
    int unBlock = 1;
    ioctlsocket(localSockOut, FIONBIO, (u_long FAR*) &unBlock);//将本地套街口设置为非阻塞

    //-----------------------------------------------
    //创建 socket 地址: localAddr表示本地服务器地址，serverAddr表示上级dns服务器地址，
    //clientAddr用于recv函数中暂存用户的地址
    SOCKADDR_IN localAddr, upperAddr, recvAddr;
    localAddr.sin_family = AF_INET;
    localAddr.sin_port = htons(PORT);
    localAddr.sin_addr.S_un.S_addr = inet_addr(LOCAL_ADDRESS);
    memset(&(localAddr.sin_zero), 0, sizeof(localAddr.sin_zero));

    //debug info
    printf("local addr ip is");
    printIp(localAddr.sin_addr);

    upperAddr.sin_family = AF_INET;
    upperAddr.sin_port = htons(PORT); 
    upperAddr.sin_addr.S_un.S_addr = inet_addr(DNS_SERVER_ADDRESS);
    memset(&(upperAddr.sin_zero), 0, sizeof(upperAddr.sin_zero));

    //debug info
    printf("upper dns addr ip is");
    printIp(upperAddr.sin_addr);

    //将socket与本机IP地址绑定（服务器地址know to all clients） 
    iResult = bind(localSock, (SOCKADDR *) & localAddr, sizeof(localAddr));
    if(iResult != 0) {
        wprintf(L"bind failed with error %d\n", WSAGetLastError());
        return 1;
    }

    //-------------------------------------------
    //发送、接收缓存
    char recvBuf[1024];
    char responseBuf[1024];
    int bufLen = 1024;
    int recvLen;

    //-------------------------------------------
    //id, 返回地址addr 缓存
    struct idAddrPair idAddrBuf[1024] = {0};
    unsigned short idAddrBufSize = 0;
    unsigned short newId;
    
    //-----------------------------------------
    //初始化cache
    struct cache cache;
    initCache(&cache);

    while(1) {
        printf("-------------------strart a new round-----------------\n");
        memset(recvBuf, 0, bufLen);

        //------------------
        //接收DNS数据包
        int recvAddrLen = sizeof(recvAddr);
        //从本地53端口听
        iResult = recvfrom(localSock, recvBuf, bufLen, 0, (struct sockaddr *) &recvAddr, &recvAddrLen);
        
        if(iResult == SOCKET_ERROR) {
            wprintf(L"recvfrom failed with error %d\n", WSAGetLastError());
            continue;
        }else if(iResult == 0) {
            printf("recv null query\n");
            continue;
        }else {
            printf("\nrecv a packet, len: %d, from PORT: %d, from ", iResult, ntohs(recvAddr.sin_port));
            printIp(recvAddr.sin_addr);
        }
        recvLen = iResult;

        if(recvAddr.sin_addr.S_un.S_addr == localAddr.sin_addr.S_un.S_addr) {
            //------------------
            //解析DNS请求packet
            struct query query = parseQuery(recvBuf);
            printf("recv a query: hostname: %s, qtype: %d, qclass: %d\n", query.hostname, query.qtype, query.qclass);

            if((query.qtype == 1) && hostnameFoundInCache(&cache, query.hostname)) {
                //在本地cache找到, 构造应答包
                printf("found in cache\n");

                //构建answer需要的参数
                //获取请求的ip地址
                unsigned int ip = inet_addr(getIpByHostname(&cache, query.hostname));
                //name在response中的位置（指针）
                unsigned short pName = 0xc00c;
                //TTL
                unsigned int TTL = 1024;
                //record length = 4, 占2字节
                unsigned short rdLen = 4;

                //构建header section
                memcpy(responseBuf, recvBuf, iResult);
                responseBuf[2] = 0x81; //标准请求应答
                if(ip == 0) { // ip == 0.0.0.0
                    responseBuf[3] = 0x83; //rcode = 3, 表示无查询结果, 实现屏蔽功能
                }else {
                    responseBuf[3] = 0x80; //rcode = 0
                }
                responseBuf[7] = 0x01; //ans count = 1 一条查询结果
                
                
                //构建answer section
                int i = iResult; // iresult 表示query长度
                memcpy(&responseBuf[i], &pName, 2);
                i += 2;
                memcpy(&responseBuf[i], &responseBuf[i - 6], 4); //type, class 和 query 中一致
                i += 4;
                memcpy(&responseBuf[i], &ip, 4);
                i += 4;
                memcpy(&responseBuf[i], &TTL, 4);
                i += 4;
                memcpy(&responseBuf[i], &rdLen, 2);
                i += 2;
                memcpy(&responseBuf[i], &ip, 4);
                i += 4;


                sendto(localSock, responseBuf, i, 0, (struct sockaddr *) &recvAddr, recvAddrLen);

            }else {
                printf("no found in cache, relay to upper DNS server\n");
                //上传给上层服务器
                //缓存id和client地址
                memcpy(&idAddrBuf[idAddrBufSize].id, recvBuf, 2);
                memcpy(&idAddrBuf[idAddrBufSize].backAddr, &recvAddr, recvAddrLen);

                //debug info
                printf("store old id %d, old PORT %d at index %d\n", ntohs(idAddrBuf[idAddrBufSize].id), ntohs(idAddrBuf[idAddrBufSize].backAddr.sin_port), idAddrBufSize);

                //把inAddrBuf的下标作为新id
                unsigned short newId = htons(idAddrBufSize);
                memcpy(recvBuf, &newId, 2);

                //debug info
                printf("old id: %d, new id %d\n", ntohs(idAddrBuf[idAddrBufSize].id) , ntohs(newId));

                idAddrBufSize = (idAddrBufSize + 1) % 1024;

                iResult = sendto(localSockOut, recvBuf, recvLen, 0, (struct sockaddr *) &upperAddr, sizeof(upperAddr));
                if(iResult == SOCKET_ERROR) {
                    printf("error code : %d\n", WSAGetLastError());
                    continue;
                }else if(iResult == 0) {
                    printf("null recv\n");
                    continue;
                }else {
                    printf("send to upper DNS server %d byte\n", iResult);
                }
                    printIp(upperAddr.sin_addr);
            }
        }
        // else {
        //     //收到上层dns的回答, 转发给用户
        //     //转换id
        //     printf("recv a response from upper DNS, %d\n", iResult);

        //     //id 就是下标
        //     memcpy(&newId, recvBuf, 2);
        //     //还原id成下标
        //     newId = ntohs(newId);
        //     memcpy(recvBuf, &idAddrBuf[newId].id, 2);

        //     sendto(localSock, recvBuf, recvLen, 0, (struct sockaddr *) &idAddrBuf[newId].backAddr, sizeof(idAddrBuf[newId].backAddr));
        // }
            //---------------------------------------------
            //接收response
            iResult = recvfrom(localSockOut, recvBuf, bufLen, 0, (struct sockaddr *) &recvAddr, &recvAddrLen);
            for(int i = 0; (iResult == SOCKET_ERROR || iResult == 0) && i < 32; i++) {
                iResult = recvfrom(localSockOut, recvBuf, bufLen, 0, (struct sockaddr *) &recvAddr, &recvAddrLen);
            }
            //收到上层dns的回答, 转发给用户
            //转换id
            if(iResult > 0) {
                printf("\nrecv a response from upper DNS, response length: %d\n", iResult);

                //id 就是下标
                memcpy(&newId, recvBuf, 2);
                //还原id成下标
                newId = ntohs(newId);
                printf("new id aka index: %d\n", newId);
                memcpy(recvBuf, &idAddrBuf[newId].id, 2);

                //debug info
                printf("access old id %d, old PORT %d\n", ntohs(idAddrBuf[newId].id), ntohs(idAddrBuf[newId].backAddr.sin_port));

                sendto(localSock, recvBuf, iResult, 0, (struct sockaddr *) &idAddrBuf[newId].backAddr, recvAddrLen);

                //debug info
                printf("send response to PORT %d, %d bytes\n", ntohs(idAddrBuf[newId].backAddr.sin_port), iResult);
            }
    }

    closeCache(&cache);
    closesocket(localSock);
    WSACleanup();	
    return 0;
}