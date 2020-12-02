#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <errno.h>
#include <libnet.h>
#include <netinet/in.h>
#include <pcap.h>
#include <stdint.h>

#define MAX_PATTERN 128

// typedef struct _tcp_pk_hdr{
//     struct libnet_ethernet_hdr eth_hdr;
//     struct libnet_ipv4_hdr ip_hdr;
//     struct libnet_tcp_hdr tcp_hdr;
//     uint8_t data[1024];
// }tcp_pk_hdr;
