#include "bitmap.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>


static pthread_mutex_t bitmap_lock = PTHREAD_MUTEX_INITIALIZER;


BitMap_t bitmap_new(unsigned int length)
{
    BitMap_t new_bits = (BitMap_t)malloc(sizeof(BitMap));
    if (new_bits == NULL)
        return NULL;

    int char_nums = sizeof(char) * (length >> 3) + 1;
    new_bits->bits = (char *)malloc(char_nums);
    if (new_bits == NULL) {
        free(new_bits);
        return NULL;
    }
    memset(new_bits->bits, 0, char_nums);
    new_bits->length = length;

    return new_bits;
}

void bitmap_destroy(BitMap_t bit)
{
    free(bit->bits);
    free(bit);
}

static unsigned int bitmap_length(BitMap_t bit)
{
    return bit->length;
}

static void bitmap_set_value(BitMap_t bit, unsigned int pos, unsigned char value)
{
    unsigned char mask = 0x80 >> (pos & 0x7);
    if (value) {
        bit->bits[pos>>3] |= mask;
    } else {
       bit->bits[pos>>3] &= ~mask;
    }
}

char bitmap_get_value(BitMap_t bit, unsigned int pos)
{
    unsigned char mask = 0x80 >> (pos & 0x7);

    return (mask & bit->bits[pos>>3]) == mask ? 1 : 0;
}

void bitmap_set(BitMap_t bit, unsigned int pos)
{
	bitmap_set_value(bit,pos,1);
}

void bitmap_clear(BitMap_t bit, unsigned int pos)
{
	bitmap_set_value(bit,pos,0);
}

static int  bitmap_get_FreePos(BitMap_t bit)
{
	int i;
	for(i=0;i<bit->length;i++)
	{
		if(bitmap_get_value(bit,i)==0)
			break;
	}
	if(i==bit->length)
		return -1;
	return i;
}

/*
* 功能：在bitmap中分配一个空闲的序号
* 返回值：分配成功，返回正数；否则返回负数
*/
int bitmap_AllocPos(BitMap_t bit)
{
	int pos;
	pthread_mutex_lock(&bitmap_lock);
	pos = bitmap_get_FreePos(bit);
	if(pos >= 0)
		bitmap_set(bit, pos);
	pthread_mutex_unlock(&bitmap_lock);
	
	return pos;
}


/*
* 功能：释放一个序号
* 返回值：释放成功，返回0；否则返回负数
*/
int bitmap_FreePos(int pos, BitMap_t bit)
{
	pthread_mutex_lock(&bitmap_lock);
	if(pos >= 0)
		bitmap_clear(bit, pos);
	pthread_mutex_unlock(&bitmap_lock);
	return 0;
}
