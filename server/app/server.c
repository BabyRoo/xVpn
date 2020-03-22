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
#include <netdb.h>
#include <netinet/in.h>
#include <semaphore.h>
#include <sys/sem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <getopt.h>

#include "bitmap.h"
#include "session.h"
#include "ringbuff.h"
#include "list.h"
#include "listbuff.h"


#define xVpn_VERSION "xVpn-v0.6"


extern char *optarg;  
extern int optind, opterr, optopt; 

static int lopt;
static int optIndex = 0;

static struct option longOpts[] = {
  { "port", optional_argument, NULL, 'p' },
  { "CAfile", optional_argument, &lopt, 1},
  { "cert", optional_argument, &lopt, 2 },
  { "key", optional_argument, &lopt, 3},
  { "version", no_argument, NULL, 'v' },
  { "help", no_argument, NULL, 'h' },
  { 0, 0, 0, 0 }
};

static int portnumber=443;

#define TEST_CA   "../ca_cert/cacert.pem"
#define TEST_CERT "../ca_cert/xvpnserver.crt"
#define TEST_KEY  "../ca_cert/xvpnserver.pem"
const char *s_cert_file = TEST_CERT, *s_key_file = TEST_KEY;
const char *CAfile = TEST_CA;

static void showUsage() {
  puts("Usage: ./xVpn --port=443 --CAfile=../ca_cert/cacert.pem --cert=../ca_cert/xvpnserver.crt --key=../ca_cert/xvpnserver.pem");
  puts("Options:");
  puts("--port          xvpn server listen port");
  puts("--CAfile        ca crt");
  puts("--cert          xvpn server crt");
  puts("--key           xvpn server private key");
  puts("--version       echo version");
  puts("--help          display this message");
}


#define IP_PROTO_ICMP    1
#define IP_PROTO_IGMP    2
#define IP_PROTO_UDP     17
#define IP_PROTO_UDPLITE 136
#define IP_PROTO_TCP     6


//IP头部，总长度20字节   
typedef struct _ip_hdr  
{  
    unsigned char version_ihl;	//版本,首部长度: version:4, ihl:4  
    unsigned char tos;       //服务类型   
    unsigned short tot_len;  //总长度   
    unsigned short id;       //标志   
    unsigned short frag_off; //分片偏移   
    unsigned char ttl;       //生存时间   
    unsigned char protocol;  //协议   
    unsigned short chk_sum;  //检验和   
    struct in_addr srcaddr;  //源IP地址   
    struct in_addr dstaddr;  //目的IP地址   
}ip_hdr;


/* The IPv6 header. */
typedef struct _ipv6_hdr {
  unsigned char v_tclass1;			// v:4, tclass1:4;
  unsigned char tclass2_flow1;	// tclass2:8, flow1:4

  unsigned short flow2;
  unsigned short len;                /* payload length */
  unsigned char nexthdr;             /* next header */
  unsigned char hoplim;              /* hop limit (TTL) */
  struct in_addr src, dest;          /* source and destination IP addresses */
}ipv6_hdr;



#define LISTENQ	200


static int tun_fd;

SSL_CTX *ctx;



struct list_head * WriteTun_ListbuffHead;
pthread_mutex_t Listbuff_lock = PTHREAD_MUTEX_INITIALIZER;
sem_t sem_WriteTun;


static int Thread_ReadTun_Flag = 0;
void * Thread_ReadTun(void *arg);
void * Thread_ReadEth(void *arg);
/*
 * Configure IP address and MTU of VPN interface /dev/tun0
 */
#define MTU 1500
void xIfconfig(void);

/*
 * Setup route table via `iptables` & `ip route`
 */
void setup_route_table(void);


/*
 * Cleanup route table
 */
void cleanup_route_table(void);

/*
 * Catch Ctrl-C and `kill`s, make sure route table gets cleaned before this process exit
 */
void cleanup(int signo);
void cleanup_when_sig_exit(void);

/*
 * Execute commands
 */
static void run(char *cmd);

/*
*
* 参数：flag参数用于指定解析成功后，buff是否由堆分配
* 当flag为0，表示buff指向ring的缓冲区；当flag为1，表示buff指向堆分配的内存.
*/
int parse_ringbuffEx2(RingBuff_t ring, char ** buff, int *len, int * flag);



typedef struct _ReadEthThreadFunc_arg{
	int connfd;
	struct sockaddr_in client_addr;
//	int status;			// 0,空闲    1,正在使用
}ReadEthThreadFuncArg_t,* pReadEthThreadFuncArg_t;



/*
 * Create VPN interface /dev/tun0 and return a fd
 */
int tun_alloc(void);


int xListen(int port);

static void dump_buff(unsigned char *buf,int size);
static void dump_ringbuff(RingBuff_t ring);
static void * Thread_ServerWriteTun(void *arg);




int  x_verification(int fd)
{
	return 0;
}


void * Tun_Handler(void *arg)
{
	arg=arg;
	struct list_head * vpnsession_head=Get_SessionHead();
	
}

/*
* 功能：在协商阶段，为客户端分配tun ip，并与client端协商
* 返回值：分配成功，返回0；否则返回-1
* 注意：需要建立全局的bitmap表来管理为客户端分配的ip；在建立session时分配，在销毁session时收回。
*/
int Negotiation_IP(struct in_addr * TunIp, int connfd, SSL *ssl)
{
	int ret;
	struct in_addr Ip;

	// 1.分配tunIP
	if(vpnsession_alloc_Tun0IP(&Ip))
	{
		fprintf(stderr,"vpnsession_alloc_Tun0IP() failed\n");
		return -1;
	}

	printf("vpnsession_alloc_Tun0IP() Completed.\n");
	// 2.发送tunIP给客户端
	char * ptr = (char *)&Ip;
	int nwritten,nleft = sizeof(Ip);
	printf("Alloc client tun ip = %d.%d.%d.%d\n",ptr[0],ptr[1],ptr[2],ptr[3]);
	
	while(nleft > 0)
	{
		nwritten=SSL_write(ssl, ptr, nleft);
		switch(SSL_get_error(ssl,nwritten)){
		case SSL_ERROR_NONE:
			nleft -= nwritten;
			ptr += nwritten;
			continue;
		default:
			printf("SSL_write error:%s\n",strerror(errno));
			SSL_free(ssl);
			close(connfd);	
			vpnsession_free_Tun0IP(&Ip);
			return -2;
		}
	}
	
	printf("发送tunIP给客户端 Completed.\n");
	// 3.检查回复
	char resp[20];		// "tunip config ok"
	ptr = resp;
	int nread;
	nleft = 15;
	memset(resp,20,0);
	while(nleft > 0)
	{
		nread = SSL_read(ssl, ptr, nleft);
		switch(SSL_get_error(ssl,nread)){
		case SSL_ERROR_NONE:
			nleft -= nread;
			ptr += nread;
			continue;
//		case SSL_ERROR_ZERO_RETURN:
//			goto finish;
		default:
			fprintf(stderr,"read from client socket failed\n");
			SSL_free(ssl);
			close(connfd);
			vpnsession_free_Tun0IP(&Ip);
			return -3;		
		}
	}

	if(memcmp(resp, "tunip config ok", 15))	// sizeof("tunip config ok")
	{
		fprintf(stderr,"recv data from client check error:%s\n",resp);
		printf("resp[0-15]=%c-%c-%c-%c-%c-%c-%c-%c-%c-%c-%c-%c-%c-%c-%c-%d\n",resp[0],resp[1],resp[2],resp[3],resp[4],resp[5],resp[6],resp[7],resp[8],resp[9],resp[10],resp[11],resp[12],resp[13],resp[14],resp[15]);
		close(connfd);
		vpnsession_free_Tun0IP(&Ip);
		return -4;
	}

	printf("tunip config Completed.\n");

	// 4.返回分配成功的tun ip
	memcpy(TunIp, &Ip, sizeof(struct in_addr));
	return 0;
}


/*
* 功能：检查该数据包是否允许通过
* 返回值：返回0，表示允许通过；否则不允许。
*/
int xAcl_check_hook(char * buf, int len);


static unsigned short X_standard_chksum(void *dataptr, unsigned short len)
{
  unsigned int acc;
  unsigned short src;
  unsigned char *octetptr;

  acc = 0;
  /* dataptr may be at odd or even addresses */
  octetptr = (unsigned char*)dataptr;
  while (len > 1) {
    /* declare first octet as most significant
       thus assume network order, ignoring host order */
    src = (*octetptr) << 8;
    octetptr++;
    /* declare second octet as least significant */
    src |= (*octetptr);
    octetptr++;
    acc += src;
    len -= 2;
  }
  if (len > 0) {
    /* accumulate remaining octet */
    src = (*octetptr) << 8;
    acc += src;
  }
  /* add deferred carry bits */
  acc = (acc >> 16) + (acc & 0x0000ffffUL);
  if ((acc & 0xffff0000UL) != 0) {
    acc = (acc >> 16) + (acc & 0x0000ffffUL);
  }
  /* This maybe a little confusing: reorder sum using htons()
     instead of ntohs() since it has a little less call overhead.
     The caller must invert bits for Internet sum ! */
  return htons((unsigned short)acc);
}

static unsigned short inet_chksum(void *dataptr, unsigned short len)
{
  return ~(X_standard_chksum(dataptr, len));
}



/*
* 功能：解析接收在ringbuff缓冲区中的数据:
*		(1)如果ip包在完整的缓冲区，则返回缓冲区中的地址；
*		(2)否则，分配一段缓冲区，并将ip包拷贝到新分配的缓冲区
* 返回值：解析ip报文成功，返回0；否则返回负数
* 注意：返回成功时，ringbuff的in/out指针没有更新
*/
static int parse_ringbuff(RingBuff_t ring, char ** buff, int *len, int * flag)
{
	int packet_len=0;
	if(!ring || !buff || !len)
	{
		printf("parse_ringbuff args error.\n");
		return -1;
	}

	ip_hdr * ip_packet = (ip_hdr *)&ring->buf[ring->out];
	int continues_valid_space;
	int in,out,CNT;
	in = ring->in;
	out = ring->out;
	CNT = ring->size;
	int data_len = (in >= out)?(in - out):(CNT + in - out);
	
	if(ring->in >= ring->out){
		continues_valid_space = ring->in - ring->out;
	}
	else{
		continues_valid_space = ring->size - ring->out;
	}
	if(data_len >= 4)							// 1.ip报文的长度字段已接收
	{
		if(continues_valid_space >= 4){			// 1.1 报文长度字段tot_len与ip头在连续缓冲区内
			packet_len = ntohs(ip_packet->tot_len);
			if(packet_len >= 64*1024){
				printf("packet_len >= 64k\n");
				return -1;
			}
			if(packet_len <= data_len){			// 1.1.1 IP包已全部接收
				if(continues_valid_space >= packet_len){	// 1.1.1.1 IP包在连续缓冲区内
					*buff = &ring->buf[out];
					*flag = 0;
				}
				else{										// 1.1.1.2 IP包不在连续缓冲区内
					char *s,*d;
					int size;
					*buff = (char *)malloc(packet_len);
					d = *buff;
					s = &ring->buf[out];
					size = CNT - out;
					memcpy(d,s,size);
					d = *buff + size;
					s = &ring->buf[0];
					size = packet_len - size;
					memcpy(d,s,size);
					*flag = 1;
				}
				*len = packet_len;
				return 0;
			}
			else{								// 1.1.2 IP包未全部接收
				return -1;
			}
		}
		else{									// 1.2 报文长度字段tot_len与ip头不在连续缓冲区内
			int tot_len_index;
			unsigned short * ptot_len;
			tot_len_index = (ring->out + 2)%(ring->size);
			ptot_len = (unsigned short *)&ring->buf[tot_len_index];
			packet_len = ntohs(*ptot_len);
			if(packet_len >= 64*1024){
				printf("packet_len >= 64k\n");
				return -1;
			}
			if(packet_len <= data_len){			// 1.2.1 IP包已全部接收
				char *s,*d;
				int size;
				*buff = (char *)malloc(packet_len);
				d = *buff;
				s = &ring->buf[out];
				size = CNT - out;
				memcpy(d,s,size);
				d = *buff + size;
				s = &ring->buf[0];
				size = packet_len - size;
				memcpy(d,s,size);
				*len = packet_len;
				*flag = 1;
				return 0;
			}
			else{								// 1.2.2 IP包未全部接收
				return -2;
			}
		}
	}
	else{										// 2.ip报文的长度字段未接收,直接返回
		return -3;
	}
}



/*
* 功能：解析接收在ringbuff缓冲区中的数据；摘取出完整ip包
* 返回值：摘取成功，返回0；否则返回负数
* 注意：返回成功时，ringbuff的in/out指针没有更新
*/
static int parse_ringbuff_v6(RingBuff_t ring, char ** buff, int *len, int * flag)
{
	int in,out,CNT;
	in = ring->in;
	out = ring->out;
	CNT = ring->size;	
	int data_len = (in >= out)?(in - out):(CNT + in - out);

	int packet_len=0;
	ipv6_hdr * ipv6_packet = (ipv6_hdr *)&ring->buf[ring->out];
	int continues_valid_space;
	if(ring->in >= ring->out){
		continues_valid_space = ring->in - ring->out;
	}
	else{
		continues_valid_space = ring->size - ring->out;
	}	

	if(data_len >= 6){										// 1.ip报文的长度字段已接收
		if(continues_valid_space >= 6){						// 	1.1 报文长度字段tot_len与ip头在连续缓冲区内
			packet_len = ntohs(ipv6_packet->len)+40;
			if(packet_len >= 64*1024){
				printf("packet_len >= 64k\n");
				return -1;
			}
			if(packet_len <= data_len){						// 	1.1.1 IP包已全部接收
				if(continues_valid_space >= packet_len){	// 	1.1.1.1 IP包在连续缓冲区内
					*buff = &ring->buf[out];
					*flag = 0;
				}
				else{										// 	1.1.1.2 IP包不在连续缓冲区内
					char *s,*d;
					int size;
					*buff = (char *)malloc(packet_len);
					d = *buff;
					s = &ring->buf[out];
					size = CNT - out;
					memcpy(d,s,size);
					d = *buff + size;
					s = &ring->buf[0];
					size = packet_len - size;
					memcpy(d,s,size);
					*flag = 1;
				}
				*len = packet_len;
				return 0;
			}
			else{											// 	1.1.2 IP包未全部接收
				return -1;
			}
		}
		else{												// 	1.2 报文长度字段tot_len与ip头不在连续缓冲区内
			int tot_len_index;
			unsigned short * ptot_len;
			tot_len_index = (ring->out + 2)%(ring->size);
			ptot_len = (unsigned short *)&ring->buf[tot_len_index];
			packet_len = ntohs(*ptot_len) + 40;
			if(packet_len >= 64*1024){
				printf("packet_len >= 64k\n");
				return -1;
			}
			if(packet_len <= data_len){						// 1.2.1 IP包已全部接收
				char *s,*d;
				int size;
				*buff = (char *)malloc(packet_len);
				d = *buff;
				s = &ring->buf[out];
				size = CNT - out;
				memcpy(d,s,size);
				d = *buff + size;
				s = &ring->buf[0];
				size = packet_len - size;
				memcpy(d,s,size);
				*flag = 1;
				*len = packet_len;
				return 0;
			}
			else{											// 1.2.2 IP包未全部接收
				return -2;
			}
		}
	}
	else													// 2.ip报文的长度字段未接收,直接返回
		return -3;
	return 0;
}


static int getip_from_buff(unsigned char * buff, struct in_addr * addr)
{
	if(!buff || !addr){
		printf("getip_from_buff args error.\n");
		return -1;
	}

	ip_hdr * ip_head = (ip_hdr *)buff;
	memcpy((void*)addr, (void*)&ip_head->dstaddr, sizeof(struct in_addr));
	return 0;
}




int main(int argc ,char *argv[])
{
	int opt;
	int option_index = 0;
	pthread_t		tid;
    int sockfd;
    struct sockaddr_in client_addr;
	const SSL_METHOD *method;

	while ( (opt = getopt_long(argc, argv, "D:", longOpts, &option_index)) != -1){
	    switch(opt){
		case 0:
			switch(lopt){
			case 1:
				CAfile = optarg;
				if(access(CAfile,R_OK)){
				  printf("--CAfile arg error\n");
				  return -1;
				}
				break;
			case 2:
				s_cert_file = optarg;
				if(access(s_cert_file,R_OK)){
				  printf("--cert arg error\n");
				  return -1;
				}
				break;
			case 3:
				s_key_file = optarg;
				if(access(s_key_file,R_OK)){
				  printf("--key arg error\n");
				  return -1;
				}
				break;
			}
		  break;
		case 'p':
		    portnumber = atoi(optarg);
			if(portnumber<=0){
			  printf("--port arg error\n");
			  return -1;
			}
		    break;
		case 'v':
	        printf("%s\n",xVpn_VERSION);
	        exit(0);
		case 'h':
	        showUsage();
	        exit(0);
		default:
	        printf("invalid args\n");
	        showUsage();
			exit(1);
	    }
	}
	printf("parse args completed.\n");

	if((session_module_init()))
	{
		fprintf(stderr,"session_module_init() failed\a\n");
		return 0;
	}
	if ((tun_fd = tun_alloc()) < 0) {
		fprintf(stderr,"tun_alloc() failed\a\n");
		return 1;
	}
	
	sockfd = xListen(portnumber);

	xIfconfig();
	setup_route_table();
	cleanup_when_sig_exit();
	{/* for ssl init */
		SSL_library_init();
	    OpenSSL_add_all_algorithms();
	    SSL_load_error_strings();

	    method = TLSv1_2_server_method();
	    ctx = SSL_CTX_new(method);
	    if (ctx == NULL) {
	        ERR_print_errors_fp(stdout);
	        exit(1);
	    }
		#if 0
	    const char *cipher_list = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384";
	    if (SSL_CTX_set_cipher_list(ctx, cipher_list) == 0) {
	        SSL_CTX_free(ctx);
	        printf("Failed to set cipher list %s", cipher_list);
	    }
		#endif
		
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);
	    /*加载CA FILE*/
	    if (SSL_CTX_load_verify_locations(ctx, CAfile, 0) != 1) {
	        SSL_CTX_free(ctx);
	        printf("Failed to load CA file %s", CAfile);
	    }
	    /*加载服务端证书*/
	    if (SSL_CTX_use_certificate_file(ctx, s_cert_file, SSL_FILETYPE_PEM) <= 0) {
			printf("use server crt file fail.\n");
	        ERR_print_errors_fp(stdout);
	        exit(1);
	    }
	    /*加载服务端私钥*/
	    if (SSL_CTX_use_PrivateKey_file(ctx, s_key_file, SSL_FILETYPE_PEM) <= 0) {
	        printf("use private key fail.\n");
	        ERR_print_errors_fp(stdout);
	        exit(1);
	    }
	    /*验证私钥*/
	    if (!SSL_CTX_check_private_key(ctx)) {
	        ERR_print_errors_fp(stdout);
	        exit(1);
	    }
	    //处理握手多次  
	    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY); 
	}

	{/* for write tun init */
		WriteTun_ListbuffHead = listbuff_create();
		if(!WriteTun_ListbuffHead)
		{
			fprintf(stderr,"listbuff_create() error\n");
			close(sockfd);
			return -2;
		}
		sem_init(&sem_WriteTun, 0, 0);		// 线程间共享，初值为0
	}

	int ret;
	if((ret=pthread_create(&tid, NULL, Thread_ReadTun, NULL))!=0)
	{
		fprintf(stderr,"pthread_create error:%s\n\a",strerror(errno));
		close(sockfd);
		return -2;
	}

	if((ret=pthread_create(&tid, NULL, Thread_ServerWriteTun, NULL))!=0)
	{
		fprintf(stderr,"pthread_create error:%s\n\a",strerror(errno));
		close(sockfd);
		return -2;
	}

	
	pReadEthThreadFuncArg_t xArg;
	for(;;)
	{
		int ret;
		int sin_size;

		xArg = (pReadEthThreadFuncArg_t)malloc(sizeof(ReadEthThreadFuncArg_t));
		printf("waiting for client connect...\n");
		memset(xArg,sizeof(ReadEthThreadFuncArg_t),0);
		sin_size=sizeof(struct sockaddr_in);
		if((xArg->connfd=accept(sockfd,(struct sockaddr *)(&xArg->client_addr),&sin_size))==-1)
		{
			fprintf(stderr,"Accept error:%s\n\a",strerror(errno));
			continue;
		}
		fprintf(stdout,"Server get connection from %s, connfd=%d\n",inet_ntoa(xArg->client_addr.sin_addr), xArg->connfd);
		if((ret=pthread_create(&tid, NULL, Thread_ReadEth, xArg))!=0)
		{
			fprintf(stderr,"pthread_create error:%s\n\a",strerror(errno));
			close(xArg->connfd);
			continue;
		}
	}
	
    close(sockfd);
	SSL_CTX_free(ctx);
	cleanup_route_table();
	listbuff_free(WriteTun_ListbuffHead);
    return 0;
}

int xWrtie(int fd, char *buff, int len)
{
	if(fd < 0 || !buff || len <=0)
		return -1;

	int nwritten,nleft;
	char * ptr;
	
	nleft = len;
	ptr = buff;
	while(nleft > 0){
		nwritten = write(fd, ptr, nleft);
		if(nwritten == 0)
			continue;
		else if(nwritten < 0 && (errno == EINTR || errno == EAGAIN))
			continue;
		else if(nwritten < 0 ){
			fprintf(stderr,"write() tun_fd error:%s\n",strerror(errno));
			// 严重错误
			return -1;
		}
		else if(nwritten > 0){
			nleft -= nwritten;
			ptr += nwritten;
		}
	}
	return 0;
}

static void * Thread_ServerWriteTun(void *arg)
{
	pNodeBuff_t pbuff;	
	pbuff=NULL;
	while(1){
		sem_wait(&sem_WriteTun);
		pthread_mutex_lock(&Listbuff_lock);
		while(1){
			pbuff = listbuff_PopNode(WriteTun_ListbuffHead);	// 从链表弹出并删除node
			if(pbuff == NULL)
				goto Thread_ClientWriteTun_exit;
//			printf("send a packet to tun,%d bytes:\n",pbuff->size);
//			dump_buff(pbuff->buff, pbuff->size);
			xWrtie(tun_fd, pbuff->buff, pbuff->size);
			nodebuff_free(pbuff);								// 释放node内存
		}
	Thread_ClientWriteTun_exit:
		pthread_mutex_unlock(&Listbuff_lock);	
	}

}



void * Thread_ReadEth(void *arg)
{
	int ret;
	SSL *ssl;
	pReadEthThreadFuncArg_t xArg = (pReadEthThreadFuncArg_t)arg;
	struct in_addr client_TunIp;
	struct in_addr client_Ip;
	int conn_fd = xArg->connfd;
	memcpy( &client_Ip, &(xArg->client_addr.sin_addr), sizeof(struct in_addr));
	free(arg);

	printf("ip=%s,conn_fd=%d\n",inet_ntoa(client_Ip),conn_fd);
	{
		ssl = SSL_new(ctx);
		if (ssl == NULL) {
			printf("SSL_new error:%s\n",strerror(errno));
			return (void *)-1;
		}
	
		SSL_set_fd(ssl, conn_fd);
		if (SSL_accept(ssl) == -1) {
			perror("accept");
			ERR_print_errors_fp(stderr); 
			SSL_free(ssl);
			close(conn_fd);
			SSL_CTX_free(ctx);
			return NULL;
		}
		printf("SSL_accept completed: Server with %s encryption\n", SSL_get_cipher(ssl));

	}
	

	// 1.验证身份
	if((ret= x_verification(conn_fd))!=0)
	{
		fprintf(stderr,"verification failed\n");
		return (void *)-1;
	}

	// 2.协商client tun IP
	if((ret=Negotiation_IP(&client_TunIp, conn_fd, ssl)) < 0)
	{
		fprintf(stderr,"Negotiation_IP failed\n");
		return (void *)-2;
	}

	printf("Negotiation_IP() completed.\n");

	// 3.创建vpn session
	pVpnSession_t CurrSession = create_vpnsession();
	if(CurrSession == NULL)
	{
		fprintf(stderr,"create_vpnsession failed\n");
		vpnsession_free_Tun0IP(&client_TunIp);
		return (void *)-3;
	}
	vpnsession_set_connfd(conn_fd, CurrSession);
	vpnsession_set_tunfd( tun_fd, CurrSession);
	vpnsession_set_clientIP( &client_Ip, CurrSession);
	vpnsession_set_Tun0IP( &client_TunIp, CurrSession);
	vpnsession_set_ssl(ssl, CurrSession);

	printf("创建vpn session completed.\n");
#define MAXLINE (66*1024)
	int nread,nwritten;
	RingBuff_t recv_ringbuff = ring_create(MAXLINE);
	while(1)
	{
		int in,out;
		int nleft ;
		int start,end;
retry_Thread_ReadEth:
		nleft = ring_continueFreeSpace(recv_ringbuff);		// 保证不回头读取数据
		in = recv_ringbuff->in;
		out = recv_ringbuff->out;
//		printf("nleft=%d,out=%d,in=%d\n",nleft,out,in);
		// 4.接收客户端数据包，并解密
		while(nleft > 0){
			nread = SSL_read(ssl, &recv_ringbuff->buf[in], nleft);
			switch(SSL_get_error(ssl,nread)){
			case SSL_ERROR_NONE:
				recv_ringbuff->in = (recv_ringbuff->in + nread) % (recv_ringbuff->size);
//				printf("out=%d,in=%d\n",recv_ringbuff->out,recv_ringbuff->in);
//				printf("read %d bytes from client ssl:\n",nread);
//				dump_ringbuff(recv_ringbuff);
				while(1){
					char * buffer;
					int packet_len,flag;
					buffer = NULL;
					packet_len = 0;
					if(parse_ringbuffEx2(recv_ringbuff, &buffer, &packet_len, &flag) == 0){
//						printf("");
						recv_ringbuff->out = (recv_ringbuff->out + packet_len) % (recv_ringbuff->size);
						pthread_mutex_lock(&Listbuff_lock);
						listbuff_PushNode(WriteTun_ListbuffHead, buffer, packet_len, flag);
						pthread_mutex_unlock(&Listbuff_lock);
						sem_post(&sem_WriteTun); 
					}
					else{
						break;
					}
				}
				goto retry_Thread_ReadEth;
			default:
				fprintf(stderr,"read from client ssl failed:nread=%d\n",nread);
				fprintf(stderr,"read() conn_fd error:%s\n",strerror(errno));
				SSL_free(ssl);
error_exit: 	// 对端关闭了套接字
				shutdown(conn_fd, SHUT_RDWR);
//				SSL_CTX_free(ctx);
				if(free_vpnsession(CurrSession))
					fprintf(stderr,"free_vpnsession error.\n");
				fprintf(stderr,"Thread_ReadEth()--free_vpnsession: nread=%d,%s\n",nread,strerror(errno));
				sleep(1);
				return (void *)-1;	
			}
		}		
	}/*while(1)*/
	sleep(1);
	return NULL;
}

/*
*
* 参数：flag参数用于指定解析成功后，buff是否由堆分配
* 当flag为0，表示buff指向ring的缓冲区；当flag为1，表示buff指向堆分配的内存.
*/
int parse_ringbuffEx2(RingBuff_t ring, char ** buff, int *len, int * flag)
{
	if(!ring || !buff || !len || !flag)
	{
		printf("parse_ringbuffEx2 args error:ring=%p,buff=%p,len=%p,flag=%p\n",ring,buff,len,flag);
		return -1;
	}
parse_again:
	if(ring->in == ring->out){
		return -2;
	}
	char ip_version;
	ip_version = ring->buf[ring->out];
	ip_version = ip_version>>4;
	if(ip_version == 4) 		// ip v4
		return parse_ringbuff(ring,buff,len, flag);
	else if(ip_version == 6)	// ip v6
		return parse_ringbuff_v6(ring,buff,len,flag);
	else{
		printf("invalid ip packet:ip_version error\n");
//		dump_ringbuff(ring);
		ring->out = (ring->out+1)%(ring->size);
		goto parse_again;
	}
	return 0;
}


static void dump_buff(unsigned char *buf,int size)
{
	unsigned char * disp_buff;
	int i;
	if((!buf) || (size == 0))
	{
		puts("arg error.");
		return;
	}
	disp_buff = (unsigned char *)malloc(3*size+2);
	for(i=0;i<size;i++)
	{
		char shi,ge;
		shi = buf[i]>>4;
		ge = buf[i]%16;
		if(shi>9)
			shi = 'a'+shi-10;
		else
			shi = '0'+shi;
		if(ge>9)
			ge = 'a'+ge-10;
		else
			ge = '0'+ge;
		disp_buff[i*3]=shi;
		disp_buff[i*3+1]=ge;
		disp_buff[i*3+2]='-';
	}
	disp_buff[3*size]='\n';
	disp_buff[3*size+1]=0;
	printf(disp_buff);
	free(disp_buff);
}

static void dump_ringbuff(RingBuff_t ring)
{
	if(!ring || ring->in == ring->out)
		return ;
	if(ring->in > ring->out)
		dump_buff(&ring->buf[ring->out], ring->in - ring->out);
	else{
		int continues_data_len;
		continues_data_len = ring->size - ring->out;
		dump_buff(&ring->buf[ring->out], continues_data_len);
		dump_buff(&ring->buf[0], ring->in);
	}
	return;
}



void * Thread_ReadTun(void *arg)
{
	SSL *ssl;
	struct in_addr destip;
	int start,end,nread;
	pVpnSession_t CurrSession;
	start=end=0;
//#define BUFF_READTUN_SIZE	(32*1024-1)
#define BUFF_READTUN_SIZE	(32*1024)
	RingBuff_t recv_ringbuff = ring_create(BUFF_READTUN_SIZE);

	while(1){
		int in ;
		
		int nleft,nread ;
		unsigned char  readtun_Buff[BUFF_READTUN_SIZE];
		unsigned char *ptr;
		int offset;
		// 1.读取tun接口的ip包
		ptr = readtun_Buff;
		nleft = BUFF_READTUN_SIZE;

readtun_again:
		nread = read(tun_fd, ptr, nleft);
		if(nread < 0 && (errno == EINTR || errno == EAGAIN))
			goto readtun_again;
		else if(nread < 0){
			// 严重错误，不应该到达此处
			fprintf(stderr,"read() tun_fd error:%s\n",strerror(errno));
			goto readtun_again;
		}
		else if(nread > 0){
			int nwritten;
//			printf("Thread_ReadTun() read %d bytes from tun:\n",nread);
//			dump_buff(readtun_Buff,nread);

			offset = 0;
			char * ip_version;
		parse_again:
			if(offset >= nread)
				continue;
			ip_version = &readtun_Buff[offset];
			if(ip_version[0] == 0x60 ){
				unsigned short * ptot_len;
				int ipv6_PackLen;
				ptot_len = (unsigned short *)&readtun_Buff[offset+4];
				ipv6_PackLen = ntohs(*ptot_len) + 40;
				offset += ipv6_PackLen;
				goto parse_again;
			}
			if(ip_version[0] != 0x45 ){
				offset += 1;
				goto parse_again;
			}
			

			if(getip_from_buff(readtun_Buff, &destip)){
				printf("ip packet invalid.\n");
				continue;
			}
//			printf("Thread_ReadTun(): destip=%s\n",inet_ntoa(destip));
			CurrSession = getsession(&destip);
			if(!CurrSession){		// 处理原则：对于无session对应的IP包，直接丢弃
				printf("no match session, drop the ip packet\n");
				continue;
			}

			ptr = readtun_Buff;
			nleft = nread;
			ssl = CurrSession->ssl;
			while(nleft > 0){
				// 2.解析成功，则写公网，回复client
				nwritten = SSL_write(ssl, ptr, nleft);
				switch(SSL_get_error(ssl,nwritten)){
				case SSL_ERROR_NONE:
					nleft -= nwritten;
					ptr += nwritten;
//					printf("write %d bytes to client ssl\n",nwritten);
					continue;
				default:
					printf("SSL_write error:%s\n",strerror(errno));
					SSL_free(ssl);
					shutdown(CurrSession->tcp_fd, SHUT_RDWR);
					if(free_vpnsession(CurrSession))
						fprintf(stderr,"free_vpnsession error.\n");
					fprintf(stderr,"Thread_ReadTun(): write() eth error--free_vpnsession().\n");
				}
			}
		
		}
		
	}
	ring_free(recv_ringbuff);
	return NULL;
}


/*
* 功能：检查该数据包是否允许通过
* 返回值：返回0，表示允许通过；否则不允许。
*/
int xAcl_check_hook(char * buf, int len)
{

	return 0;
}


int xListen(int port)
{
    struct sockaddr_in server_addr;
	int sockfd=0;
	if((sockfd=socket(AF_INET,SOCK_STREAM,0))==-1)
    {
        fprintf(stderr,"Socket error:%s\n\a",strerror(errno));
		return 0;
    }
    bzero(&server_addr,sizeof(struct sockaddr_in));
    server_addr.sin_family=AF_INET;
    server_addr.sin_addr.s_addr=htonl(INADDR_ANY);
    server_addr.sin_port=htons(port);
    if(bind(sockfd,(struct sockaddr *)(&server_addr),sizeof(struct sockaddr))==-1)
    {
        fprintf(stderr,"Bind error:%s\n\a",strerror(errno));
		close(sockfd);
		return 0;
    }
    if(listen(sockfd,LISTENQ)==-1)
    {
        fprintf(stderr,"Listen error:%s\n\a",strerror(errno));
		close(sockfd);
		return 0;
    }
	return sockfd;

}


/*
 * Create VPN interface /dev/tun0 and return a fd
 */
int tun_alloc(void) {
  struct ifreq ifr;
  int fd, e;

  if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
    perror("Cannot open /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  strncpy(ifr.ifr_name, "tun0", IFNAMSIZ);

  if ((e = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
    perror("ioctl[TUNSETIFF]");
    close(fd);
    return e;
  }

  return fd;
}

/*
 * Configure IP address and MTU of VPN interface /dev/tun0
 */
void xIfconfig(void) {
  char cmd[1024];
  snprintf(cmd, sizeof(cmd), "ifconfig tun0 10.8.0.1/16 mtu %d up", MTU);
  run(cmd);
  /*
  snprintf(cmd, sizeof(cmd), "sysctl -w net.ipv6.conf.tun0.disable_ipv6=1");
  run(cmd);
  run(cmd);
  run(cmd);
  */
}

/*
 * Setup route table via `iptables` & `ip route`
 */
void setup_route_table(void) {
  run("sysctl -w net.ipv4.ip_forward=1");

#ifdef AS_CLIENT
  run("iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE");
  run("iptables -I FORWARD 1 -i tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT");
  run("iptables -I FORWARD 1 -o tun0 -j ACCEPT");
  char cmd[1024];
  snprintf(cmd, sizeof(cmd), "ip route add %s via $(ip route show 0/0 | sed -e 's/.* via \([^ ]*\).*/\1/')", SERVER_HOST);
  run(cmd);
  run("ip route add 0/1 dev tun0");
  run("ip route add 128/1 dev tun0");
#else
  run("iptables -t nat -A POSTROUTING -s 10.8.0.0/16 ! -d 10.8.0.0/16 -m comment --comment 'xvpn' -j MASQUERADE");
  run("iptables -A FORWARD -s 10.8.0.0/16 -m state --state RELATED,ESTABLISHED -j ACCEPT");
  run("iptables -A FORWARD -d 10.8.0.0/16 -j ACCEPT");
#endif
}


/*
 * Cleanup route table
 */
void cleanup_route_table(void) {
#ifdef AS_CLIENT
  run("iptables -t nat -D POSTROUTING -o tun0 -j MASQUERADE");
  run("iptables -D FORWARD -i tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT");
  run("iptables -D FORWARD -o tun0 -j ACCEPT");
  char cmd[1024];
  snprintf(cmd, sizeof(cmd), "ip route del %s", SERVER_HOST);
  run(cmd);
  run("ip route del 0/1");
  run("ip route del 128/1");
#else
  run("iptables -t nat -D POSTROUTING -s 10.8.0.0/16 ! -d 10.8.0.0/16 -m comment --comment 'xvpn' -j MASQUERADE");
  run("iptables -D FORWARD -s 10.8.0.0/16 -m state --state RELATED,ESTABLISHED -j ACCEPT");
  run("iptables -D FORWARD -d 10.8.0.0/16 -j ACCEPT");
#endif
}


/*
 * Catch Ctrl-C and `kill`s, make sure route table gets cleaned before this process exit
 */
void cleanup(int signo) {
  printf("Goodbye, cruel world....\n");
  if (signo == SIGHUP || signo == SIGINT || signo == SIGTERM) {
  	listbuff_free(WriteTun_ListbuffHead);
    cleanup_route_table();
    exit(0);
  }
}

void cleanup_when_sig_exit(void) {
  struct sigaction sa;
  sa.sa_handler = &cleanup;
  sa.sa_flags = SA_RESTART;
  sigfillset(&sa.sa_mask);

  if (sigaction(SIGHUP, &sa, NULL) < 0) {
    perror("Cannot handle SIGHUP");
  }
  if (sigaction(SIGINT, &sa, NULL) < 0) {
    perror("Cannot handle SIGINT");
  }
  if (sigaction(SIGTERM, &sa, NULL) < 0) {
    perror("Cannot handle SIGTERM");
  }
}


/*
 * Execute commands
 */
static void run(char *cmd) {
  printf("Execute `%s`\n", cmd);
  if (system(cmd)) {
    perror(cmd);
    exit(1);
  }
}



