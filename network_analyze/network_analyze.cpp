// network_analyze.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "pcap.h"
#include <winsock2.h>

#pragma comment(lib, "ws2_32.lib")

#define ETHERTYPE_IP 0x0800 /* ip protocol */
#define TCP_PROTOCAL 0x0600 /* tcp protocol */
#define ETHER_ADDR_LEN 6
#define BUFFER_MAX_LENGTH 65536
/*
* define struct of ethernet header , ip address , ip header and tcp header
*/
/* ethernet header */
typedef struct ether_header {
	u_char ether_shost[ETHER_ADDR_LEN]; /* source ethernet address, 8 bytes */
	u_char ether_dhost[ETHER_ADDR_LEN]; /* destination ethernet addresss, 8 bytes */
	u_short ether_type;                 /* ethernet type, 16 bytes */
} ether_header;

/* four bytes ip address */
typedef struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* ipv4 header */
typedef struct ip_header {
	u_char ver_ihl;         /* version and ip header length */
	u_char tos;             /* type of service */
	u_short tlen;           /* total length */
	u_short identification; /* identification */
	u_short flags_fo;       // flags and fragment offset
	u_char ttl;             /* time to live */
	u_char proto;           /* protocol */
	u_short crc;            /* header checksum */
	struct in_addr saddr;       /* source address */
	struct in_addr daddr;       /* destination address */
	u_int op_pad;           /* option and padding */
}ip_header;

/* tcp header */
//typedef struct tcp_header {
//	u_short th_sport;         /* source port */
//	u_short th_dport;         /* destination port */
//	u_int th_seq;             /* sequence number */
//	u_int th_ack;             /* acknowledgement number */
//	u_short th_len_resv_code; /* datagram length and reserved code */
//	u_short th_window;        /* window */
//	u_short th_sum;           /* checksum */
//	u_short th_urp;           /* urgent pointer */
//}tcp_header;

// TCP header
typedef struct tcp_header
{
	unsigned short source_port; // source port
	unsigned short dest_port; // destination port
	unsigned int sequence; // sequence number - 32 bits
	unsigned int acknowledge; // acknowledgement number - 32 bits

	unsigned char ns : 1; //Nonce Sum Flag Added in RFC 3540.
	unsigned char reserved_part1 : 3; //according to rfc
	unsigned char data_offset : 4; /*The number of 32-bit words in the TCP header.
								   This indicates where the data begins.
								   The length of the TCP header is always a multiple
								   of 32 bits.*/

	unsigned char fin : 1; //Finish Flag
	unsigned char syn : 1; //Synchronise Flag
	unsigned char rst : 1; //Reset Flag
	unsigned char psh : 1; //Push Flag
	unsigned char ack : 1; //Acknowledgement Flag
	unsigned char urg : 1; //Urgent Flag

	unsigned char ecn : 1; //ECN-Echo Flag
	unsigned char cwr : 1; //Congestion Window Reduced Flag

						   ////////////////////////////////

	unsigned short window; // window
	unsigned short checksum; // checksum
	unsigned short urgent_pointer; // urgent pointer
} TCP_HDR;

/* packet handler 函数原型 */
/* 每次捕获到数据包时，libpcap都会自动调用这个回调函数 */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm *ltime;
	char timestr[50];
	time_t local_tv_sec;

	ether_header * eheader = (ether_header*)pkt_data; /* transform packet data to ethernet header */
	if (eheader->ether_type != htons(ETHERTYPE_IP)) { /* ip packet only */
		return;
	}
	ip_header * ih = (ip_header*)(pkt_data + 14); /* get ip header */
	if (ih->proto != htons(TCP_PROTOCAL)) { /* tcp packet only */
		return;
	}

	/* 将时间戳转换成可识别的格式 */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%Y-%m-%d %H:%M:%S", ltime);

	printf("%s,%.3d len:%d\n", timestr, header->ts.tv_usec / 1000, header->len);

	int ip_len = ntohs(ih->tlen); /* get ip length, it contains header and body */

	char* ip_pkt_data = (char*)ih;
	char buffer[BUFFER_MAX_LENGTH];
	int bufsize = 0;

	printf("---------IP协议---------\n");
	printf("版本号:%d\n", ih->ver_ihl);
	printf("总长度:%d\n", ntohs(ih->tlen));
	printf("协议类型:%d\n", ih->proto);
	printf("检验和:%d\n", ntohs(ih->crc));
	printf("源IP地址:%s\n", inet_ntoa(ih->saddr));
	printf("目的地址:%s\n", inet_ntoa(ih->daddr));
	ip_len = (ih->ver_ihl & 0xf) * 4;
	tcp_header *th = (tcp_header *)((u_char*)ih + ip_len);
	u_short sport, dport;
	/* 将网络字节序列转换成主机字节序列 */
	sport = ntohs(th->th_sport);
	dport = ntohs(th->th_dport);
	printf("tcp: src port %d dst port %d\n", sport, dport);
	return;
}

int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fcode;
	char packet_filter[] = "ip and tcp";
	u_int netmask;

	/* 获取本机设备列表 */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* 打印列表 */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* 跳转到选中的适配器 */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

	/* 打开设备 */
	if ((adhandle = pcap_open(d->name,          // 设备名
		65536,            // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
		PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
		1000,             // 读取超时时间
		NULL,             // 远程机器验证
		errbuf            // 错误缓冲池
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL) {
		// 获得接口的第一个地址的掩码  
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	} else {
		netmask = 0xffffff;
	}
	//// 编译过滤器  
	//if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0) {
	//	fprintf(stderr, "\nUnable to compile the packet filter.Check the syntax\n");
	//	pcap_freealldevs(alldevs);
	//	return -1;
	//}

	//// 设置过滤器  
	//if (pcap_setfilter(adhandle, &fcode) < 0) {
	//	fprintf(stderr, "\nError setting the filter.\n");
	//	pcap_freealldevs(alldevs);
	//	return -1;
	//}

	printf("\nlistening on %s...\n", d->description);

	/* 释放设备列表 */
	pcap_freealldevs(alldevs);

	/* 开始捕获 */
	pcap_loop(adhandle, 0, packet_handler, NULL);

	return 0;
}

