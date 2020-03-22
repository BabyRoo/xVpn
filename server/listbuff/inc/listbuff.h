#ifndef __LISTBUFF_H__
#define __LISTBUFF_H__

#include "list.h"

typedef struct _nodebuff
{
  struct list_head node;
  int size;
  char * buff;
} NodeBuff_t,* pNodeBuff_t;


struct list_head * listbuff_create(void);

/*
* 功能：释放整个list
*/
int listbuff_free(struct list_head * listbuffer_head);

/*
* 功能：删除指定的node
*/
int nodebuff_free(pNodeBuff_t node_buffer);

/*
* 功能：返回该list上的节点数
*/
int listbuff_GetNodeCnt(struct list_head *List);


/*
* 功能:添加一个节点
*/
int listbuff_PushNode(struct list_head *List, char * buff, int len, int flag);


/*
* 功能:删除/弹出一个节点
* 注意：与listbuff_PushNode()配合，是node采用FIFO方式管理
*/
pNodeBuff_t listbuff_PopNode(struct list_head *List);

/*
* 功能:尝试是否有node
* 返回值：返回正值，表示有node
*/
int listbuff_TryHaveNode(struct list_head *List);




#endif
