#include "printarr.h"
#include <stdio.h>

int printarr(unsigned char* arr, int length )
{
	int i;
	for (int i = 0; i < length; ++i)
	{
		printf("%2x ",arr[i]);
	}
	printf("\n");
	return 0;
}