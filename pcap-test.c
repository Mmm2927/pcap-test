#include <netinet/in.h>
#include <pcap.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>

#define ETHER_ADDR_LEN      0x6
#define ETHER_HEADER_LEN    0xE

#define IPv4_ADDR_LEN	    0x4

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

struct ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

struct ipv4_hdr
{
    u_int8_t ip_hl:4,      /* header length */
       ip_v:4;         /* version */
    u_int8_t ip_tos;       /* type of service */
#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY      0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT    0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY   0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST       0x02
#endif
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
#ifndef IP_RF
#define IP_RF 0x8000        /* reserved fragment flag */
#endif
#ifndef IP_DF
#define IP_DF 0x4000        /* dont fragment flag */
#endif
#ifndef IP_MF
#define IP_MF 0x2000        /* more fragments flag */
#endif 
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
#endif
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    u_int8_t ip_src[IPv4_ADDR_LEN];
    u_int8_t ip_dst[IPv4_ADDR_LEN];
};

struct tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
    
    u_int8_t th_x2:4,        /* data offset */
           th_off:4;         
    u_int8_t  th_flags;       /* control flags */

#ifndef TH_FIN
#define TH_FIN    0x01      /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN    0x02      /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST    0x04      /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08      /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK    0x10      /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG    0x20      /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE    0x40
#endif
#ifndef TH_CWR   
#define TH_CWR    0x80
#endif
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		
		//check Ethernet header
		struct ethernet_hdr eht;
		int skip = 0;

		memcpy(&eht, packet, ETHER_HEADER_LEN);
		if(htons(eht.ether_type) == 0x0800){

			//check IPv4 header
			struct ipv4_hdr ipv4;
			skip += ETHER_HEADER_LEN;
			memcpy(&ipv4, packet+skip, 20);
			if(ipv4.ip_p == 0x6){

				//check tcp header
				struct tcp_hdr tcp;
				skip += (ipv4.ip_hl * 32 / 8);
				memcpy(&tcp, packet+skip, 20);
				
				skip += tcp.th_off * 32 / 8;

				//print data
				printf("Ethernet des mac - %02x:%02x:%02x:%02x:%02x:%02x , src mac - %02x:%02x:%02x:%02x:%02x:%02x\n", 
						eht.ether_dhost[0],
						eht.ether_dhost[1],
						eht.ether_dhost[2],
						eht.ether_dhost[3],
						eht.ether_dhost[4],
						eht.ether_dhost[5],
						eht.ether_shost[0],
						eht.ether_shost[1],
						eht.ether_shost[2],
						eht.ether_shost[3],
						eht.ether_shost[4],
						eht.ether_shost[5]);
				printf("IPv4 src ip - %d.%d.%d.%d , dst ip - %d.%d.%d.%d\n",
						ipv4.ip_src[0],
						ipv4.ip_src[1],
						ipv4.ip_src[2],
						ipv4.ip_src[3],
						ipv4.ip_dst[0],
						ipv4.ip_dst[1],
						ipv4.ip_dst[2],
						ipv4.ip_dst[3]);
				printf("TCP src port - %d , dst port - %d\n",
						tcp.th_sport,
						tcp.th_dport);
				
				if(header->caplen > skip){
					int print_len = (header->caplen-skip)%8;
					printf("Data - ");
					for(int i = skip; i <= skip + print_len; i++)
						printf("%02x ", packet[i]);
					printf("\n");
				}
				
				printf("\n\n");

			}
		}
	}
	pcap_close(pcap);
}
