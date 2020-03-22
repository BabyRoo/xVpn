#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include "session.h"
#include "ringbuff.h"
#include "bitmap.h"
#include "list.h"



#define BITMAP_LEN	8

//VpnSession_t G_Session[BITMAP_LEN*8];
static struct list_head G_SessionHead;
static int SESSION_CNT=0;

static pthread_mutex_t sessionlist_lock = PTHREAD_MUTEX_INITIALIZER;

static BitMap_t TunIP_BitMap=NULL;
static pthread_mutex_t Bitmap_lock = PTHREAD_MUTEX_INITIALIZER;






/*
* 功能：session模块初始化
* 内容：
*	1.初始化session链表头
*	2.初始化session计数
*	3.初始化bitmap，用于ip分配
*/
int session_module_init(void)
{
	INIT_LIST_HEAD(&G_SessionHead);
	SESSION_CNT=0;
	if((TunIP_BitMap = bitmap_new(BITMAP_LEN)) == NULL)
	{
		perror("bitmap_new error");
		return -1;
	}
	bitmap_set(TunIP_BitMap,1);		// 将10.8.0.1保留给vpn server
	bitmap_set(TunIP_BitMap,0);

	return 0;
}

/*
* 功能：session模块反初始化
* 内容：
*	1.释放session内存
*	2.释放listbuff内存
*/
int session_module_exit(void)
{
	// 1.释放session内存

	// 2.释放listbuff内存

	return 0;
}


/*
* 功能：获取session链表
*
*
*/
struct list_head * Get_SessionHead(void)
{
	return &G_SessionHead;
}


/*
* 功能：建立vpn_session结构
*/
pVpnSession_t create_vpnsession(void)
{
	if(SESSION_CNT >= (BITMAP_LEN*8))		// 最多支持(BITMAP_LEN*8)个session
		return NULL;
	pVpnSession_t vpnsession = (pVpnSession_t)malloc(sizeof(VpnSession_t));
	if(!vpnsession)
		return NULL;
	vpnsession->status = 0;
	INIT_LIST_HEAD(&(vpnsession->listbuff_head));	// 初始化listbuff链表
	pthread_mutex_init(&vpnsession->session_lock, NULL);
	pthread_mutex_lock(&sessionlist_lock);
	list_add(&(vpnsession->node),&G_SessionHead);	// 添加到session链表
	SESSION_CNT++;
	pthread_mutex_unlock(&sessionlist_lock);
	return vpnsession;
}

int free_listbuffer(struct list_head * head)
{
	if(!head)
		return -1;
	struct list_head *p;
	list_for_each(p, head) {
		pListBuff_t pbuff = list_entry(p,ListBuff_t,node);
		pbuff->size = 0;
		free(pbuff->buff);
		free(pbuff);
		pbuff = 0;
	}
	
}




/*
* 功能：释放vpn_session结构
* return 0:成功 否则返回负数
*/
int free_vpnsession(pVpnSession_t vpnsession)
{
	if(!vpnsession)
		return -1;
	struct list_head * p=&(vpnsession->node);
	if(!p)
		return -2;
	if((!p->next)||(!p->prev))
		return -3;
	pthread_mutex_lock(&sessionlist_lock);
	pthread_mutex_lock(&vpnsession->session_lock);
	if(vpnsession->status < 0)
	{
		pthread_mutex_unlock(&vpnsession->session_lock);
		pthread_mutex_unlock(&sessionlist_lock);
		perror("vpnsession have been free.\n");
		return -4;
	}
	list_del(p);
	free_listbuffer(&vpnsession->listbuff_head);
	vpnsession_free_Tun0IP(&vpnsession->tun0_ip);	// 释放tun0ip，释放相应bitmap位置
	vpnsession->status = -2;						// 负值，表示该session无效
	pthread_mutex_unlock(&vpnsession->session_lock);
	free(vpnsession);
	SESSION_CNT--;
	pthread_mutex_unlock(&sessionlist_lock);
	return 0;
}


int vpnsession_PushPacketEx(RingBuff_t         recv_ring,int start, int end, pVpnSession_t psession)
{
	if((!recv_ring)||(start < 0)||(end < 0))
	{
#ifdef VPNSESSION_DEBUG
	printf("vpnsession_PushPacket() error:recv_ring=%p,start=%d,end=%d\n",recv_ring,start,end);
#endif
	return -1;
	}	

	pListBuff_t plistbuffer = (pListBuff_t)malloc(sizeof(ListBuff_t));
	if(!plistbuffer)
	{
#ifdef VPNSESSION_DEBUG
	printf("vpnsession_PushPacket() error:malloc() failed\n");
#endif
	return -2;
	}

	int len;
	if(end > start)
		len = end - start + 1;
	else{
		len = (end + recv_ring->size) - (start) + 1;
	}
	
	pthread_mutex_lock(&psession->session_lock);
	plistbuffer->size = len;

	char * buffer = (char *)malloc(len);
	if(!buffer)
	{
#ifdef VPNSESSION_DEBUG
	printf("vpnsession_PushPacket() error:malloc() failed\n");
#endif
	return -3;
	}

	int i,j;
	int LEN = recv_ring->size;
	for(i=0;i<len;i++){
		j=start%LEN;
		buffer[i] = recv_ring->buf[j];
		start++;
	}
	plistbuffer->buff = buffer;
	list_add(&plistbuffer->node,&psession->listbuff_head);
	pthread_mutex_unlock(&psession->session_lock);

	return 0;
}

int vpnsession_PushPacket(unsigned char * packet,int len, pVpnSession_t psession)
{
	if((!packet)||(len < 0))
	{
#ifdef VPNSESSION_DEBUG
	printf("vpnsession_PushPacket() error:packet=%p,len=%d\n",packet,len);
#endif
	return -1;
	}

	pListBuff_t plistbuffer = (pListBuff_t)malloc(sizeof(ListBuff_t));
	if(!plistbuffer)
	{
#ifdef VPNSESSION_DEBUG
	printf("vpnsession_PushPacket() error:malloc() failed\n");
#endif
	return -2;
	}
	
	pthread_mutex_lock(&psession->session_lock);
	plistbuffer->size = len;
	
	char * buffer = (char *)malloc(len);
	if(!buffer)
	{
#ifdef VPNSESSION_DEBUG
	printf("vpnsession_PushPacket() error:malloc() failed\n");
#endif
	return -3;
	}
	
	memcpy(buffer,packet,len);
	plistbuffer->buff = buffer;
	list_add(&plistbuffer->node,&psession->listbuff_head);
	pthread_mutex_unlock(&psession->session_lock);

	return 0;
}


/*
* 功能：从session中弹出一个ip报文
* 返回值：返回0，表示执行成功。此时packet参数指向vpnsession_PopPacket内部malloc的内存；len为packet的长度
* 	      返回负数，表示执行失败
* 注意：调用者应该free packet参数指向的内存。
*/
int vpnsession_PopPacket(unsigned char * packet, int * len, pVpnSession_t psession)
{
	if((!psession)||(*len < 0))
	{
#ifdef VPNSESSION_DEBUG
	printf("vpnsession_PopPacket() error:packet=%p,*len=%d, psession=%p\n",packet,*len, psession);
#endif
	return -1;
	}

	pthread_mutex_lock(&psession->session_lock);
	struct list_head * prev = psession->listbuff_head.prev;		// 不能采用list_next_entry()，否则不是FIFO
	if (!prev || prev == &psession->listbuff_head)
	{
#ifdef VPNSESSION_DEBUG
		printf("vpnsession_PopPacket() error:prev=%p, psession->listbuff_head=%p\n", prev, &psession->listbuff_head);
#endif
		return -4;
	}
	pListBuff_t listbuff = list_entry(prev,ListBuff_t,node);

	*len = listbuff->size;
	if(*len <= 0)
	{
#ifdef VPNSESSION_DEBUG
			printf("vpnsession_PopPacket() error: *len error\n");
#endif
		return -3;
	}
	
	unsigned char * data = (unsigned char *)malloc(*len);
	if(!data)
	{
#ifdef VPNSESSION_DEBUG
		printf("vpnsession_PopPacket() error:data malloc() error\n");
#endif
		return -2;
	}
	memcpy(data,listbuff->buff,*len);

	list_del(prev);			// 获取数据后，应删除该节点
	free(listbuff->buff);
	free(listbuff);

	pthread_mutex_unlock(&psession->session_lock);
	packet = data;
	return 0;

}

int vpnsession_set_connfd(int connfd, pVpnSession_t psession)
{
	if(psession && connfd > 0)
		psession->tcp_fd = connfd;
	else
		return -1;
	return 0;
}

int vpnsession_set_tunfd(int tunfd, pVpnSession_t psession)
{
	if(psession && tunfd > 0)
		psession->tun_fd = tunfd;
	else
		return -1;
	return 0;
}

int vpnsession_set_clientIP(struct in_addr * clientIP, pVpnSession_t psession)
{
	if(clientIP && psession)
	{
		memcpy(&psession->client_ip, clientIP, sizeof(struct in_addr));
		return 0;
	}
	return -1;
}


int vpnsession_set_Tun0IP(struct in_addr * Tun0IP, pVpnSession_t psession)
{
	if(Tun0IP && psession)
	{
		memcpy(&psession->tun0_ip, Tun0IP, sizeof(struct in_addr));
		return 0;
	}
	return -1;

}

int vpnsession_set_ssl(SSL *ssl, pVpnSession_t psession)
{
	if(psession && ssl )
		psession->ssl = ssl;
	else
		return -1;
	return 0;
}



/*
* 功能：为客户端tun分配ip地址
* 返回值：为0，表示分配成功；否则分配失败
*/
int vpnsession_alloc_Tun0IP(struct in_addr * Tun0IP)
{
	int ip = bitmap_AllocPos(TunIP_BitMap);
	if(ip < 0){
		printf("bitmap_AllocPos() error,ret=%d\n",ip);
		return ip;
	}
	char * bytes = (char *)Tun0IP;
	bytes[0] = 10;			// 10.8.0.x
	bytes[1] =  8;
	bytes[2] =  0;
	bytes[3] = ip;

	return 0;	
}


/*
* 功能：回收客户端tun的ip地址
* 返回值：为0，表示分配成功；否则分配失败
*/
int vpnsession_free_Tun0IP(struct in_addr * Tun0IP)
{
	char * byte = (char *)Tun0IP;
	int ip = byte[3];
	
	return bitmap_FreePos(ip, TunIP_BitMap);
}


pVpnSession_t getsession(struct in_addr *destip)
{
	if(!destip)
		return NULL;

	unsigned int ip1,ip2;
	ip1 = *((unsigned int*)destip);
	struct list_head *p;
	pVpnSession_t pSession;
	list_for_each(p, &G_SessionHead) {
		pSession = list_entry(p,VpnSession_t,node);
		ip2=*((unsigned int*)(&pSession->tun0_ip));
		if(ip1 == ip2)
			return pSession;
	}

	return NULL;

}



