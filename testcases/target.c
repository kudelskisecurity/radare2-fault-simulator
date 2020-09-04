#include "stdio.h"
#include "string.h"
#include "stdint.h"

// Simple check vulnerable to simple skip.
uint8_t check1(uint8_t * src, uint8_t * dst)
{
	uint8_t i = 0, res = 0;
	for(i=0; i<8; i++) {
		res |= (src[i] ^ dst[i]);
	}
	return res;
}

// Double check vulnerable to simple skip during comparison.
uint8_t check2(uint8_t * src, uint8_t * dst)
{
	uint8_t i = 0, res1 = 0, res2 = 0;
	for(i=0; i<8; i++) {
		res1 |= src[i] ^ dst[i];
	}

    for(i=0; i<8; i++) {
		res2 |= src[i] ^ dst[i];
	}
    
    if (res1 != 0 || res2 != 0)
    {
	    return 1;
    }
    else
    {
        return 0;
    }
}

// Double check not vulnerable to simple skip.
uint8_t check3(uint8_t * src, uint8_t * dst)
{
	uint8_t i = 0, res1 = 0, res2 = 0;
	for(i=0; i<8; i++) {
		res1 |= src[i] ^ dst[i];
	}

    for(i=0; i<8; i++) {
		res2 |= src[i] ^ dst[i];
	}
    
    if (res1 == 0 && res2 == 0)
    {
	    return 0;
    }
    else
    {
        return 1;
    }
}

void main(int argc, char * argv[])
{
	uint8_t source[8] =      {7,9,4,0,1,8,1,2};
	uint8_t destination[8] = {7,2,3,4,5,6,7,8};

	// Change check function here
	if(check1(source, destination)) {
		printf("Bad boy\r\n");
	} else {
		printf("Good boy\r\n");
	}
}
