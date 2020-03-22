/**
 **/

#ifndef __BITMAP_H__
#define __BITMAP_H__

/**
 *存储bitmap的结构体
 *存储的顺序从左至右
 **/

typedef struct _Bits {
    char *bits;
    int length;
}BitMap,* BitMap_t;


/**
 *获得bitmap
 *@length bitmap的长度
 *@return 所有位都初始化为0的bitmap
 */
BitMap_t bitmap_new(unsigned int length);

/**
 *销毁一个bitmap
 **/
void bitmap_destroy(BitMap_t bit);

/**
 *获得y一个bitmap的长度
 *@bit 需要获得长度的bitmap
 *@return bit的长度
 **/
//unsigned int bitmap_length(BitMap_t bit);

/**
 *设置bitmap中相应位置的值
 *@bit 待设置的bitmap
 *@pos  需要设置的位置
 **/
//void bitmap_set_value(BitMap_t bit, unsigned int pos, unsigned char value);

/**
 *设置bitmap中相应位置的值
 *@bit  待获取的bitmap
 *@pos  获取的位置
 **/

char bitmap_get_value(BitMap_t bit, unsigned int pos);


void bitmap_set(BitMap_t bit, unsigned int pos);

void bitmap_clear(BitMap_t bit, unsigned int pos);


/**
 * 查找空闲可用的pos值
 *@bit  待获取的bitmap
 *@return 空闲可用的pos值，查找失败返回-1
 **/
//static int bitmap_get_FreePos(BitMap_t bit);

/*
* 功能：在bitmap中分配一个空闲的序号
* 返回值：分配成功，返回0；否则返回负数
*/
int bitmap_AllocPos(BitMap_t bit);

/*
* 功能：释放一个序号
* 返回值：释放成功，返回0；否则返回负数
*/
int bitmap_FreePos(int index, BitMap_t bit);



#endif /*_BITS_H_*/

