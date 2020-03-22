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
#include "listbuff.h"


struct list_head * listbuff_create(void)
{
	struct list_head * list = (struct list_head * )malloc(sizeof(struct list_head ));
	if (list > 0)
	{
		INIT_LIST_HEAD(list);	// 初始化listbuff链表
		return list;
	}
	else
		return NULL;
}


int listbuff_free(struct list_head * listbuffer_head)
{
	if(!listbuffer_head)
		return -1;
	struct list_head *p;
	// 1.释放node内存
	list_for_each(p, listbuffer_head) {
		pNodeBuff_t pbuff = list_entry(p,NodeBuff_t,node);
		list_del(p);				// 从链表删除node
		nodebuff_free(pbuff);		// 释放node内存
	}
	// 2.释放list head
	free(listbuffer_head);
	listbuffer_head = NULL;
	return 0;
}

int nodebuff_free(pNodeBuff_t node_buffer)
{
	if(!node_buffer)
		return -1;
	node_buffer->size = 0;
	free(node_buffer->buff);
	node_buffer->buff = NULL;
	free(node_buffer);
	node_buffer = NULL;
	return 0;
}




/*
* 功能:添加一个节点
* 参数：flag为1，表示buff指向的内存为堆内存,可以直接使用
*/
int listbuff_PushNode(struct list_head *List, char * buff, int len, int flag)
{
	if(!List || !buff || len <= 0)
		return -1;
	char * data;
	if(!flag){
		data= (char *)malloc(len);
		if(data==NULL){
			printf("listbuff_PushNode():malloc(%d) error\n",len);
			return -2;
		}
		memcpy(data, buff, len);
	}
	else{
		data = buff;
	}
	pNodeBuff_t node_buffer = (pNodeBuff_t)malloc(sizeof(NodeBuff_t));
	if(node_buffer == NULL)
		return -3;
	node_buffer->buff = data;
	node_buffer->size = len;
	list_add(&node_buffer->node, List);

	return 0;
}


/*
* 功能:删除/弹出一个节点
* 注意：与listbuff_PushNode()配合，使node采用FIFO方式管理
*/
pNodeBuff_t listbuff_PopNode(struct list_head *List)
{
	if(!List)
		return NULL;
	struct list_head * prev = List->prev;
	if(prev == List)
		return NULL;
	pNodeBuff_t pbuff = list_entry(prev, NodeBuff_t, node);
	list_del(&pbuff->node);	
	return pbuff;
	
}

/*
* 功能:尝试是否有node
* 返回值：返回正值，表示有node
*/
int listbuff_TryHaveNode(struct list_head *List)
{
	if(!List)
		return 0;
	if(List->next != List)
		return 1;
	return 0;
}


/*
* 功能：返回该list上的节点数
*/
int listbuff_GetNodeCnt(struct list_head *listbuffer_head)
{
	if (!listbuffer_head)
		return 0;
	struct list_head *p;
	int cnt=0;
	list_for_each(p, listbuffer_head) {
		cnt++;
	}

	return cnt;
}


