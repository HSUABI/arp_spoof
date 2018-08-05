#include "swap_endian.h"

int swap_word_endian(unsigned short swapper)
{
	unsigned short swappee = swapper << 8 | swapper >> 8 ;
	return swappee;
}
