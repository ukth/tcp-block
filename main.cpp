#include "main.h"


struct tcp_pk_hdr{
    struct libnet_ethernet_hdr eth_hdr;
    struct libnet_ipv4_hdr ip_hdr;
    struct libnet_tcp_hdr tcp_hdr;
    uint8_t data[1024];
};

char pattern[MAX_PATTERN];
int pattern_len = 0;
pcap_t* handle;




void usage() {
	printf("syntax : tcp-block <interface> <pattern>\n");
	printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}


int ban_pkt(u_char* p){
	for(int i = 0; i < 32; i++){

		if(strncmp(pattern, (char*)p+i, pattern_len) == 0){
			return 1;
		}
	}
	return 0;
}

void print_tcp(struct libnet_tcp_hdr tcp_hdr, u_char* payload){

	printf("tcp src port: %d\n", ntohs(tcp_hdr.th_sport));
	printf("tcp dst port: %d\n\n", ntohs(tcp_hdr.th_dport));

	printf("data:\n");


	for(int i =0; i < 16; i++){
		printf("%02x ", *(payload+i));
	}

	printf("\n\n########################################\n\n");

}


void block_packet(libnet_ethernet_hdr eth_hdr, libnet_ipv4_hdr ipv4_hdr, libnet_tcp_hdr tcp_hdr){
	tcp_pk_hdr packet;
    packet.eth_hdr = eth_hdr;
    packet.ip_hdr = ipv4_hdr;
    packet.tcp_hdr = tcp_hdr;

    printf("Blocked\n");

    packet.tcp_hdr.th_seq += ntohs(packet.ip_hdr.ip_len);
    packet.tcp_hdr.th_flags |= TH_RST;
    pcap_inject(handle, reinterpret_cast<const u_char*>(&packet), ntohs(packet.ip_hdr.ip_len)+LIBNET_ETH_H);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(tcp_pk_hdr));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return;
    }

}


int main(int argc, char* argv[]) {
    if (argc != 3) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    memcpy(pattern, argv[2], MAX_PATTERN);
    pattern_len = strlen(pattern);

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;

        struct libnet_ethernet_hdr eth_hdr;
        struct libnet_ipv4_hdr ipv4_hdr;
        struct libnet_tcp_hdr tcp_hdr;

        const u_char* packet;
        u_char* p;

        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        p = (u_char*)packet;
        memcpy(&eth_hdr, p, 14);
        p += 14;
        memcpy(&ipv4_hdr, p, 20);
        p += 20;
        memcpy(&tcp_hdr, p, 20);
        p += tcp_hdr.th_off * 4;


        if(ban_pkt(p)){
        	block_packet(eth_hdr, ipv4_hdr, tcp_hdr);
        }


    }
    pcap_close(handle);

}