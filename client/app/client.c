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
#include <semaphore.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <getopt.h>

#include "ringbuff.h"
#include "listbuff.h"


#define xVpn_VERSION "xVpnClient-v0.6"


extern char *optarg;  
extern int optind, opterr, optopt;  

static int lopt;
static int optIndex = 0;

static struct option longOpts[] = {
  { "vpnserver", required_argument, NULL, 's' },
  { "serverport", optional_argument, NULL, 'p' },
  { "vpn", required_argument, NULL, 'n' },
  { "CAfile", optional_argument, &lopt, 1},
  { "cert", optional_argument, &lopt, 2 },
  { "key", optional_argument, &lopt, 3},
  { "version", no_argument, NULL, 'v' },
  { "help", no_argument, NULL, 'h' },
  { 0, 0, 0, 0 }
};


static int VPN_PORT = 443;

#define TEST_CA   "../ca_cert/cacert.pem"
#define TEST_CERT "../ca_cert/xvpnusr1.crt"
#define TEST_KEY  "../ca_cert/xvpnusr1.pem"

const char *s_cert_file = TEST_CERT, *s_key_file = TEST_KEY;
const char *CAfile = TEST_CA;
char * vpnserverIP = NULL;
char * vpnNets = NULL;


void showUsage() {
  puts("Usage: ./xVpnClient --vpn=192.168.132.0 --vpnserver=192.168.56.114 --serverport=443 --CAfile=../ca_cert/cacert.pem --cert=../ca_cert/xvpnusr1.crt --key=../ca_cert/xvpnusr1.pem");
  puts("Options:");
  puts("--vpnserver		xvpnserver ip address");
  puts("--serverport    xvpn server port");
  puts("--vpn        	vpn net");
  puts("--CAfile     	ca crt");
  puts("--cert			xvpn user crt");
  puts("--key			xvpn user private key");
  puts("--version       echo version");
  puts("--help          display this message");
}


static struct in_addr tun0Ip;


#define MTU 1500


static struct in_addr * p_addr;

struct list_head * WriteTun_ListbuffHead;
pthread_mutex_t Listbuff_lock = PTHREAD_MUTEX_INITIALIZER;
sem_t sem_WriteTun;


int tunfd;
int tcp_fd;


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



/*
 * Create VPN interface /dev/tun0 and return a fd
 */
int tun_alloc() {
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

void ShowCerts(SSL * ssl)
{
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL) {
        printf("数字证书信息:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("证书: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("颁发者: %s\n", line);
        free(line);
        X509_free(cert);
    } else {
        printf("无证书信息！\n");
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

static int max(int a, int b) {
  return a > b ? a : b;
}

int xWrtie(int fd, char *buff, int len);


/*
 * For a real-world VPN, traffic inside UDP tunnel is encrypted
 * A comprehensive encryption is not easy and not the point for this demo
 * I'll just leave the stubs here
 */
void encrypt(char *plantext, char *ciphertext, int len) {
  memcpy(ciphertext, plantext, len);
}

void decrypt(char *ciphertext, char *plantext, int len) {
  memcpy(plantext, ciphertext, len);
}


/*
 * Configure IP address and MTU of VPN interface /dev/tun0
 */
void ifconfig() {
  char cmd[1024];
  unsigned char * p = (unsigned char *)&tun0Ip;
  snprintf(cmd, sizeof(cmd), "ifconfig tun0 10.8.0.%d/16 mtu %d up", p[3], MTU);
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
static void setup_route_table() {
  run("sysctl -w net.ipv4.ip_forward=1");
  run("iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE");
  char cmd[1024];
  snprintf(cmd, sizeof(cmd), "ip route add %s/24 dev tun0", vpnNets);
  run(cmd);
}

/*
 * Cleanup route table
 */
static void cleanup_route_table() {
  run("iptables -t nat -D POSTROUTING -o tun0 -j MASQUERADE");
  char cmd[1024];
  snprintf(cmd, sizeof(cmd), "ip route del %s/24 dev tun0", vpnNets);
  run(cmd);

}


/*
 * Catch Ctrl-C and `kill`s, make sure route table gets cleaned before this process exit
 */
static void cleanup(int signo) {
  printf("Goodbye, cruel world....\n");
  if (signo == SIGHUP || signo == SIGINT || signo == SIGTERM) {
  	listbuff_free(WriteTun_ListbuffHead);
    cleanup_route_table();
    exit(0);
  }
}

void cleanup_when_sig_exit() {
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
* 功能：与vpn服务器完成握手。协商出tun0的IP地址，并完成ip和路由的配置
* 返回：返回0表示成功；否则表示握手失败
*/
int ClientNegotiation_IP(int fd, SSL *ssl);


void * Thread_ClientReadTun(void *arg);
void * Thread_ClientWriteTun(void *arg);


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
		if(continues_valid_space >= 4){ 		// 1.1 报文长度字段tot_len与ip头在连续缓冲区内
			packet_len = ntohs(ip_packet->tot_len);
			if(packet_len >= 64*1024){
				printf("packet_len >= 64k\n");
				return -1;
			}
			if(packet_len <= data_len){ 		// 1.1.1 IP包已全部接收
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
			if(packet_len <= data_len){ 		// 1.2.1 IP包已全部接收
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
		if(continues_valid_space >= 6){ 					//	1.1 报文长度字段tot_len与ip头在连续缓冲区内
			packet_len = ntohs(ipv6_packet->len)+40;
			if(packet_len >= 64*1024){
				printf("packet_len >= 64k\n");
				return -1;
			}
			if(packet_len <= data_len){ 					//	1.1.1 IP包已全部接收
				if(continues_valid_space >= packet_len){	//	1.1.1.1 IP包在连续缓冲区内
					*buff = &ring->buf[out];
					*flag = 0;
				}
				else{										//	1.1.1.2 IP包不在连续缓冲区内
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
			else{											//	1.1.2 IP包未全部接收
				return -1;
			}
		}
		else{												//	1.2 报文长度字段tot_len与ip头不在连续缓冲区内
			int tot_len_index;
			unsigned short * ptot_len;
			tot_len_index = (ring->out + 2)%(ring->size);
			ptot_len = (unsigned short *)&ring->buf[tot_len_index];
			packet_len = ntohs(*ptot_len) + 40;
			if(packet_len >= 64*1024){
				printf("packet_len >= 64k\n");
				return -1;
			}
			if(packet_len <= data_len){ 					// 1.2.1 IP包已全部接收
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



/*
*
* 参数：flag参数用于指定解析成功后，buff是否由堆分配
* 当flag为0，表示buff指向ring的缓冲区；当flag为1，表示buff指向堆分配的内存.
*/
int parse_ringbuffEx2(RingBuff_t ring, char ** buff, int *len, int * flag)
{
	if(!ring || !buff || !len )
	{
		printf("parse_ringbuffEx2 args error.\n");
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
//		printf("shi=%d,ge=%d\n",shi,ge);
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
//		printf("shi=%d,ge=%d\n",shi,ge);
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





int main(int argc ,char *argv[])
{
	int opt;
	int option_index = 0;
	SSL_CTX *ctx;
    SSL *ssl;
    const SSL_METHOD *method;

	while ( (opt = getopt_long(argc, argv, "D:", longOpts, &option_index)) != -1){
		struct in_addr server_sin_addr;
		struct in_addr vpn_sin_addr;
		switch(opt){
		case 0:
			switch(lopt){
			case 1:
			CAfile = optarg;
			printf("CAfile=%s\n",CAfile);
			if(access(CAfile,R_OK)){
				printf("--CAfile arg error\n");
				return -1;
			}
			break;
		case 2:
			s_cert_file = optarg;
			printf("s_cert_file=%s\n",s_cert_file);
			if(access(s_cert_file,R_OK)){
				printf("--cert arg error\n");
				return -1;
			}
			break;
		case 3:
			s_key_file = optarg;
			printf("s_key_file=%s\n",s_key_file);
			if(access(s_key_file,R_OK)){
				printf("--key arg error\n");
				return -1;
			}
			break;
			}
			break;
		case 'p':
			VPN_PORT = atoi(optarg);
			if(VPN_PORT<=0){
				printf("--port arg error\n");
				return -1;
			}
			break;
		case 's':
			vpnserverIP = optarg;
			if(inet_aton(vpnserverIP,&server_sin_addr) == 0){
				printf("--vpnserver arg error\n");
				exit(1);
			}
			break;
		case 'n':
			vpnNets = optarg;
			if(inet_aton(vpnNets,&vpn_sin_addr) == 0){
				printf("--vpn arg error\n");
				exit(1);
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
	if(!vpnserverIP || !vpnNets){
		printf("must set --vpnserver --vpn args\n\n");
		showUsage();
		return -1;
	}

	tunfd = tun_alloc();
	if(tunfd<=0)
	{
		puts("tunfd error");
		return -1;
	}

	{
		SSL_library_init();
	    SSL_load_error_strings();
	    OpenSSL_add_all_algorithms();  
	    method = TLSv1_2_client_method();
	    ctx = SSL_CTX_new(method);
		if (!ctx) {
	        printf("create ctx is failed.\n");
			return -2;
	    }
	#if 0
		const char * cipher_list = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:AES128-GCM-SHA256:RC4:HIGH:!MD5:!aNULL:!EDH";
		if (SSL_CTX_set_cipher_list(ctx, cipher_list) == 0) {
			SSL_CTX_free(ctx);
			printf("Failed to set cipher list: %s", cipher_list);
		}
	#endif
		/*设置会话的握手方式*/ 
	    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);

	    /*加载CA FILE*/
	    if (SSL_CTX_load_verify_locations(ctx, CAfile, 0) != 1) {
	        SSL_CTX_free(ctx);
	        printf("Failed to load CA file %s", CAfile);
	    }
	    if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
	        SSL_CTX_free(ctx);
	        printf("Call to SSL_CTX_set_default_verify_paths failed");
	    }
	    /*加载客户端证书*/
	    if (SSL_CTX_use_certificate_file(ctx, s_cert_file, SSL_FILETYPE_PEM) != 1) {
	        SSL_CTX_free(ctx);
	        printf("Failed to load client certificate from %s", s_cert_file);
	    }
	    /*加载客户端私钥*/
	    if (SSL_CTX_use_PrivateKey_file(ctx, s_key_file, SSL_FILETYPE_PEM) != 1) {
	        SSL_CTX_free(ctx);
	        printf("Failed to load client private key from %s", s_key_file);
	    }
	    /*验证私钥*/
	    if (SSL_CTX_check_private_key(ctx) != 1) {
	        SSL_CTX_free(ctx);
	        printf("SSL_CTX_check_private_key failed");
	    }
	    /*处理握手多次*/  
	    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY); 

	}


	struct sockaddr_storage client_addr;
	socklen_t client_addrlen = sizeof(client_addr);

	struct sockaddr_in server_addr;
	tcp_fd =socket(AF_INET,SOCK_STREAM,0);	// IPPROTO_TCP
	if(tcp_fd<0)
	{
		printf("create socket error\n");
		return -2;
	}
	server_addr.sin_family=AF_INET;
	server_addr.sin_port=htons(VPN_PORT);
	struct in_addr server_sin_addr;
	inet_aton(vpnserverIP,&server_sin_addr);		// inet_ntoa();
	server_addr.sin_addr=server_sin_addr;
	/*发起连接服务器*/
	if(connect(tcp_fd,(struct sockaddr *)(&server_addr),sizeof(struct sockaddr))==-1)
    {
		fprintf(stderr,"Connect error:%s\n",strerror(errno));
		goto error_exit;
		exit(1);
    }
	{
		/*创建SSL*/
	    ssl = SSL_new(ctx);
	    if (ssl == NULL) {
	        printf("SSL_new error.\n");
	    }
	    /*将fd添加到ssl层*/
	    SSL_set_fd(ssl, tcp_fd);
	    if (SSL_connect(ssl) == -1) {
	        printf("SSL_connect fail.\n");
	        ERR_print_errors_fp(stderr);
	    } else {
	        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
	        ShowCerts(ssl);
	    }
	}


	if(ClientNegotiation_IP(tcp_fd, ssl)){
		fprintf(stderr,"ClientNegotiation_IP error:%s\n",strerror(errno));
		goto error_exit;
	}

	{
		WriteTun_ListbuffHead = listbuff_create();
		if(!WriteTun_ListbuffHead)
		{
			fprintf(stderr,"listbuff_create() error\n");
			goto error_exit;
		}
		sem_init(&sem_WriteTun, 0, 0);		// 线程间共享，初值为0
	}
	
	
	int ret;
	pthread_t		tid;
	if((ret=pthread_create(&tid, NULL, Thread_ClientReadTun, ssl))!=0)
	{
		fprintf(stderr,"pthread_create error:%s\n\a",strerror(errno));
		goto error_exit;
	}

	if((ret=pthread_create(&tid, NULL, Thread_ClientWriteTun, NULL))!=0)
	{
		fprintf(stderr,"pthread_create error:%s\n\a",strerror(errno));
		goto error_exit;
	}

	printf("connect to xVpnServer success...\n");
	
	#define MAXLINE (66*1024)
	int nread,nwritten;
	RingBuff_t recv_ringbuff = ring_create(MAXLINE);
	while(1){
		int in, out;
		int nleft ;
		int start,end;
		
	retry_Thread_ReadEth:
		nleft = ring_continueFreeSpace(recv_ringbuff);		// 保证不回头读取数据
		in = recv_ringbuff->in;
		out = recv_ringbuff->out;
		// 4.接收客户端数据包，并解密
		while(nleft > 0){
			nread = SSL_read(ssl, &recv_ringbuff->buf[in], nleft);
			switch(SSL_get_error(ssl,nread)){
			case SSL_ERROR_NONE:
				recv_ringbuff->in = (recv_ringbuff->in + nread) % (recv_ringbuff->size);
				while(1){
					char * buffer;
					int packet_len,flag;
					buffer = NULL;
					packet_len = 0;
					if(parse_ringbuffEx2(recv_ringbuff, &buffer, &packet_len, &flag) == 0){
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
				fprintf(stderr,"read from server ssl failed:nread=%d\n",nread);
				fprintf(stderr,"read() conn_fd error:%s\n",strerror(errno));
				SSL_free(ssl);
				goto error_exit;
			}
		}

	}
	
	return 0;
error_exit:
	shutdown(tcp_fd, SHUT_RDWR);
	SSL_CTX_free(ctx);
	sleep(1);
	cleanup_route_table();
	return -1;
}


int xWrtie(int fd, char *buff, int len)
{
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

void * Thread_ClientWriteTun(void *arg)
{
	pNodeBuff_t pbuff;
	
	pbuff=NULL;
	while(1){
		sem_wait(&sem_WriteTun);
		pthread_mutex_lock(&Listbuff_lock);
		while(1){
			pbuff = listbuff_PopNode(WriteTun_ListbuffHead);
			if(pbuff == NULL)
				goto Thread_ClientWriteTun_exit;
			xWrtie(tunfd, pbuff->buff, pbuff->size);
			nodebuff_free(pbuff);		// 释放node内存
		}
	Thread_ClientWriteTun_exit:
		pthread_mutex_unlock(&Listbuff_lock);	
	}

}

void * Thread_ClientReadTun(void *arg)
{
	SSL * ssl=(SSL*)arg;
	char buff[1024*64];
	int nleft,nread,nwritten;
	char * ptr;
	int offset;

	while(1){
		nleft = 1024*64;
		ptr = buff;
	readtun_again:
		nread = read(tunfd, ptr, nleft);
		if(nread<0 && errno == EINTR)
			goto readtun_again;
		else if(nread > 0){
//			printf("read %d bytes from tun:\n",nread);
//			dump_buff(buff, nread);
		
			offset = 0;
			char * ip_version;
		parse_again:
			if(offset >= nread)
				continue;
			ip_version = &buff[offset];
			if(ip_version[0] == 0x60 ){
				unsigned short * ptot_len;
				int ipv6_PackLen;
				ptot_len = (unsigned short *)&buff[offset+4];
				ipv6_PackLen = ntohs(*ptot_len) + 40;
				offset += ipv6_PackLen;
//				printf("nread=%d,ipv6_PackLen=%d,offset=%d\n",nread,ipv6_PackLen,offset);
				goto parse_again;
			}
			if(ip_version[0] != 0x45 ){
				offset += 1;
				goto parse_again;
			}

//			printf("deal with ipv4\n");
			nleft = nread - offset;
			ptr = buff + offset;
			while(nleft > 0){
				nwritten = SSL_write(ssl, ptr, nleft);
				switch(SSL_get_error(ssl,nwritten)){
				case SSL_ERROR_NONE:
					nleft -= nwritten;
					ptr += nwritten;
					continue;
				default:
					printf("SSL_write error:%s\n",strerror(errno));
					SSL_shutdown(ssl);
					SSL_shutdown(ssl);
					SSL_free(ssl);
					shutdown(tcp_fd, SHUT_RDWR);
					break;
				}
			}
		}
		else{
			perror("read tun_fd error");
			close(tunfd);
			shutdown(tcp_fd, SHUT_RDWR);
			return NULL;
		}
	}
}


/*
* 功能：与vpn服务器完成握手。协商出tun0的IP地址，并完成ip和路由的配置
* 返回：返回0表示成功；否则表示握手失败
*/
int ClientNegotiation_IP(int fd, SSL *ssl)
{
	// 1.接收服务端的消息
	unsigned char * ptr = (char *)&tun0Ip;
	int nread, nleft;
	nleft = sizeof(tun0Ip);
	memset(ptr,nleft,0);
	while(nleft > 0)
	{
		nread = SSL_read( ssl, ptr, nleft);
		switch(SSL_get_error(ssl,nread)){
		case SSL_ERROR_NONE:
			nleft -= nread;
			ptr += nread;
			continue;
		default:
			fprintf(stderr,"read from client socket failed\n");
			SSL_free(ssl);
			close(fd);
			return -3;		
		}
	}	

	// 2.确认ip地址信息
	ptr = (char *)&tun0Ip;
	printf("tun0Ip[0:3]=%d.%d.%d.%d\n",ptr[0],ptr[1],ptr[2],ptr[3]);
	if((ptr[0]!=10)&&(ptr[1]!=8)&&(ptr[2]!=0)){		// // 10.8.0.x
		fprintf(stderr,"tun ip addr msg error\n");
		close(fd);
		return -3;
	}
	// 3.配置ip地址、配置路由信息
	ifconfig();
	setup_route_table();
	cleanup_when_sig_exit();

	// 4.发送配置完成消息
	int nwritten;
	char mesg[] = "tunip config ok";
	ptr = mesg;
	nleft = 15;	// sizeof(mesg)
//	printf("sizeof(mesg)=%d\n",nleft);
	while(nleft > 0){
		nwritten = SSL_write(ssl, ptr, nleft);
		switch(SSL_get_error(ssl,nwritten)){
		case SSL_ERROR_NONE:
			nleft -= nwritten;
			ptr += nwritten;
			continue;
		default:
			printf("SSL_write error:%s\n",strerror(errno));
			SSL_free(ssl);
			close(fd);	
			return -2;
		}
	}
	
	return 0;
}





