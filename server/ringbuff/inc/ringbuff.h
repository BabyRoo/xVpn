#ifndef __RINGBUFF_H__
#define __RINGBUFF_H__

typedef signed char __int8_t;
typedef unsigned char __uint8_t;
typedef signed short int __int16_t;
typedef unsigned short int __uint16_t;
typedef signed int __int32_t;
typedef unsigned int __uint32_t;
typedef unsigned long __uint64_t;

typedef __uint8_t uint8_t;
typedef __uint16_t uint16_t;
typedef __uint32_t uint32_t;
typedef __uint64_t uint64_t;
typedef int bool_t;


typedef struct _ringbuff{
	unsigned int len;		// current length
	unsigned int in;
	unsigned int out;
	unsigned int size;		// TOTAL SIZE
	unsigned char * buf;
}RingBuff,* RingBuff_t;

RingBuff_t ring_create(unsigned int len);
void ring_free(RingBuff_t ring);

uint32_t ring_write(RingBuff * ring,uint8_t *buffer,uint32_t len);
uint32_t ring_write_char(RingBuff * ring,uint8_t ch);
uint32_t ring_read(RingBuff *ring,uint8_t *buffer,uint32_t len);
char ring_read_char(RingBuff *ring);
uint32_t ring_valid_freespace(RingBuff *ring);
uint32_t ring_check(RingBuff *ring);
bool_t ring_if_full(RingBuff *ring);
bool_t ring_if_empty(RingBuff *ring);
/*
功能：清除环形缓冲区中所有数据，本函数只是把环形缓冲区的读写指针归零，并没有
实际覆盖缓冲区中的数据。
*/
void ring_flush(RingBuff *ring);


/*
功能：读指针从当前位置开始，向前移动指定长度，释放掉被跳过的数据，相当于哑读
      了 len 个字节。如果缓冲区中的数据量不足，则全部释放。
参数： ring，目标环形缓冲区指针。
       len，释放的数据数量。
返回：实际释放的数据量。
*/
uint32_t ring_dumb_read(RingBuff *ring,uint32_t len);

/*
功能：返回当前能连续使用的缓冲区size（即不回头的连续空间）
参数： ring，目标环形缓冲区指针。
返回：当前能连续使用的缓冲区size。
*/
int ring_continueFreeSpace(RingBuff *ring);


/*
功能：从环形缓冲区的当前读位置开始，查找字符 c 的位置。
参数： ring，目标环形缓冲区指针。
       c，需查找的字符。
返回：如果找到，返回 c 出现的位置（相对于当前读指针的增量），如果没有找到则返回 cn_limit_uint32
*/
//uint32_t ring_search_ch(RingBuff *ring, char c);


/*
功能：从 ring 当前读位置开始查找字符序列的位置，字符序列可以包含字符 0，不是以0 结束的字符串，而是指定序列长度。
参数： ring，目标环形缓冲区指针。
	   string，需查找的字符序列。
	   str_len，字符序列长度。
返回：如果找到，返回 str 出现的位置（相对于当前读指针的增量），如果没有找到则返回 cn_limit_uint32。
*/
//uint32_t ring_search_str(RingBuff *ring, char *string,uint32_t str_len);




#endif