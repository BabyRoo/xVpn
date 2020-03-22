#ifndef __SESSION_H__
#define __SESSION_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>

#include <openssl/ssl.h>
#include <openssl/err.h>


#include "list.h"

#define VPNSESSION_DEBUG	1


/*
typedef struct _session{
	int client_fd;			// 远端客户fd
	char client_ip[4];		// 远端客户ip
	int vpn_tun_fd;			// vpn server fd
	char destlocal_ip[4];	// vpn server内网目的ip地址
}vpn_session;
*/

typedef struct _listbuff
{
  struct list_head node;
  int size;
  char * buff;
} ListBuff_t,* pListBuff_t;





/*
struct in_addr server_sin_addr;
inet_aton(VPN_IP,&server_sin_addr);		// inet_ntoa();
*/

typedef struct _session{
  int tcp_fd;       		 // client和vpn建立的连接
  int tun_fd;				 // 服务端的tun句柄
  SSL *ssl;					 // ssl
  struct in_addr tun0_ip;    // 协商出的tun0地址
  struct in_addr client_ip;  // 客户端的地址
  int status;        		 // 表示该session是否有效。为1表示有效
  pthread_mutex_t session_lock;	// 本session的锁
  struct list_head node;	 // session链表
  struct list_head listbuff_head;	 // 表示该session上需要回复用户的数据帧集合
//  ListBuff_t listbuff_reply; 
}VpnSession_t,* pVpnSession_t;

/*
* 功能：建立vpn_session结构
*/
pVpnSession_t create_vpnsession(void);

void vpnsession_setTcpFd(int tcp_fd);
void vpnsession_setTunFd(int tun_fd);
void vpnsession_setTun_ip(struct in_addr * tun_ip);
void vpnsession_setClient_ip(struct in_addr * client_ip);
int vpnsession_set_ssl(SSL *ssl, pVpnSession_t psession);


/*
* 功能：释放listbuffer结构
* return 0:成功 否则返回负数
*/
int free_listbuffer(struct list_head * head);

/*
* 功能：释放vpn_session结构
* return 0:成功 否则返回负数
*/
int free_vpnsession(pVpnSession_t vpnsession);

int vpnsession_PushPacket(unsigned char * packet,int len, pVpnSession_t psession);
int vpnsession_PopPacket(unsigned char * packet, int * len, pVpnSession_t psession);

struct list_head * Get_SessionHead(void);

int vpnsession_set_connfd(int connfd, pVpnSession_t psession);
int vpnsession_set_tunfd(int tunfd, pVpnSession_t psession);
int vpnsession_set_clientIP(struct in_addr * clientIP, pVpnSession_t psession);
int vpnsession_set_Tun0IP(struct in_addr * Tun0IP, pVpnSession_t psession);

int vpnsession_alloc_Tun0IP(struct in_addr * Tun0IP);
int vpnsession_free_Tun0IP(struct in_addr * Tun0IP);


pVpnSession_t getsession(struct in_addr *destip);

/*
* 功能：session模块初始化
* 内容：
*	1.初始化session链表头
*	2.初始化session计数
*	3.初始化bitmap，用于ip分配
*/
int session_module_init(void);


#endif
