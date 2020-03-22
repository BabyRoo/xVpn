#include "ringbuff.h"
#include <stdio.h>
#include <stdlib.h>


RingBuff_t ring_create(unsigned int len)
{
	if(len<0)
		return NULL;
	RingBuff_t ring=(RingBuff_t)malloc(sizeof(RingBuff));
	if(!ring)
		return NULL;
	ring->buf = (unsigned char *)malloc(len);
	if(!ring->buf)
	{
		free(ring);
		return NULL;
	}
	ring->in=0;
	ring->out=0;
	ring->len = 0;
	ring->size = len;
	return ring;
}

void ring_free(RingBuff_t ring)
{
	if(ring)
	{
		free(ring->buf);
		free(ring);
	}
}


uint32_t ring_write(RingBuff * ring,uint8_t *buffer,uint32_t len)
{
	int i;
	if((!ring)||(!buffer)||(len<=0))
		return 0;
	uint32_t space = ring_valid_freespace(ring);
	uint32_t ret = (space > len)?len:space;
	for(i=0;i<ret;i++)
	{
		ring->buf[ring->in] = buffer[i];
		ring->in = (ring->in+1)%(ring->size);
	}
	ring->len += ret;
	return ret;
}

uint32_t ring_write_char(RingBuff * ring,uint8_t ch)
{
	return ring_write(ring,&ch,1);
}


uint32_t ring_read(RingBuff *ring,uint8_t *buffer,uint32_t len)
{
	int i;
	if((!ring)||(!buffer)||(len<=0))
		return 0;
	uint32_t valid_datasize = ring_check(ring);
	uint32_t ret = (valid_datasize > len)?len:valid_datasize;
	for(i=0;i<ret;i++)
	{
		buffer[i] = ring->buf[ring->out];
		ring->out = (ring->out+1)%(ring->size);
	}
	ring->len -= ret;
	return ret;
}

char ring_read_char(RingBuff *ring)
{
	char ch;
	uint32_t ret = ring_read(ring, &ch, 1);
	if(ret==1)
		return ch;
	else
		return -1;
}


// 返回空余空间
uint32_t ring_valid_freespace(RingBuff *ring)
{
	if(!ring)
		return 0;
	return (ring->size-ring->len);
}


// 返回有效数据size
uint32_t ring_check(RingBuff *ring)
{
	if(!ring)
		return 0;
	return (ring->len);
}

bool_t ring_if_full(RingBuff *ring)
{
	if(ring->size==ring->len)
		return 1;
	else
		return 0;
}


bool_t ring_if_empty(RingBuff *ring)
{
	if(0==ring->len)
		return 1;
	else
		return 0;

}


/*
功能：清除环形缓冲区中所有数据，本函数只是把环形缓冲区的读写指针归零，并没有
实际覆盖缓冲区中的数据。
*/
void ring_flush(RingBuff *ring)
{
	if(ring)
	{
		ring->len=0;
		ring->in=0;
		ring->out=0;
	}
}



/*
功能：读指针从当前位置开始，向前移动指定长度，释放掉被跳过的数据，相当于哑读
      了 len 个字节。如果缓冲区中的数据量不足，则全部释放。
参数： ring，目标环形缓冲区指针。
       len，释放的数据数量。
返回：实际释放的数据量。
*/
uint32_t ring_dumb_read(RingBuff *ring,uint32_t len)
{
	int i;
	if((!ring)||(len<=0))
		return 0;
	uint32_t valid_datasize = ring_check(ring);
	uint32_t ret = (valid_datasize > len)?len:valid_datasize;
	ring->out = (ring->out+ret)%(ring->size);
	ring->len -= ret;

}

int ring_continueFreeSpace(RingBuff *ring)
{
	if(ring->in >= ring->out)
		return (ring->size - ring->in);
	else
		return (ring->out - ring->in);
}


//uint32_t ring_search_ch(RingBuff *ring, char c);
//uint32_t ring_search_str(RingBuff *ring, char *string,uint32_t str_len);


