#include "protocol_check.h"
#define IPPROTO_TCP 0X06
#define ETHERTYPE_IP 0X0800
#define ETHERTYPE_ARP 0X0806

int ip_check(unsigned short type)
{
	return type==ETHERTYPE_IP ? 1: 0 ;
}

int arp_check(unsigned short type)
{
	return type==ETHERTYPE_ARP ? 1: 0 ;
}

int tcp_check(unsigned short protocol)
{
	return protocol==IPPROTO_TCP ? 1: 0;
}
