﻿// network_analyze.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "pcap.h"
#include <winsock2.h>

#pragma comment(lib, "ws2_32.lib")

//some packet processing functions
void ProcessPacket(const u_char*, int); //This will decide how to digest

void print_ethernet_header(const u_char*);
void PrintIpHeader(const u_char*, int);
void PrintIcmpPacket(const u_char*, int);
void print_udp_packet(const u_char*, int);
void PrintTcpPacket(const u_char*, int);
void PrintData(const u_char*, int);

// Set the packing to a 1 byte boundary
//#include "pshpack1.h"
//Ethernet Header
typedef struct ethernet_header
{
	UCHAR dest[6];
	UCHAR source[6];
	USHORT type;
}   ETHER_HDR, *PETHER_HDR, FAR * LPETHER_HDR, ETHERHeader;

//Ip header (v4)
typedef struct ip_hdr
{
	unsigned char ip_header_len : 4; // 4-bit header length (in 32-bit words) normally=5 (Means 20 Bytes may be 24 also)
	unsigned char ip_version : 4; // 4-bit IPv4 version
	unsigned char ip_tos; // IP type of service
	unsigned short ip_total_length; // Total length
	unsigned short ip_id; // Unique identifier

	unsigned char ip_frag_offset : 5; // Fragment offset field

	unsigned char ip_more_fragment : 1;
	unsigned char ip_dont_fragment : 1;
	unsigned char ip_reserved_zero : 1;

	unsigned char ip_frag_offset1; //fragment offset

	unsigned char ip_ttl; // Time to live
	unsigned char ip_protocol; // Protocol(TCP,UDP etc)
	unsigned short ip_checksum; // IP checksum
	unsigned int ip_srcaddr; // Source address
	unsigned int ip_destaddr; // Source address
} IPV4_HDR;

//UDP header
typedef struct udp_hdr
{
	unsigned short source_port; // Source port no.
	unsigned short dest_port; // Dest. port no.
	unsigned short udp_length; // Udp packet length
	unsigned short udp_checksum; // Udp checksum (optional)
} UDP_HDR;

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

typedef struct icmp_hdr
{
	BYTE type; // ICMP Error type
	BYTE code; // Type sub code
	USHORT checksum;
	USHORT id;
	USHORT seq;
} ICMP_HDR;
// Restore the byte boundary back to the previous value
//#include <poppack.h>

FILE *logfile;
int tcp = 0, udp = 0, icmp = 0, others = 0, igmp = 0, total = 0, i, j;
struct sockaddr_in source, dest;
char hex[2];

//Its free!
ETHER_HDR *ethhdr;
IPV4_HDR *iphdr;
TCP_HDR *tcpheader;
UDP_HDR *udpheader;
ICMP_HDR *icmpheader;
const u_char *data;

const char client_ip[] = "192.168.1.100";

struct data_head {
	int unuse;
	char type;	//包类型
	int areano;		//区号
	int record;//记录数//sww20060410复用,当上传挂失信息时,为发卡中心区号
	int maxflowno;	//最大流水号
	int size;	//数据缓存大小
	// add check code, by wjzhe
	u_int32_t crc;		//CRC校验，校验内容为数据包内容。如果数据包为空，这里填0
	char reserved[2]; //保留字，填0
	u_int8_t chk_add;		 //包头累加和校验，内容包括type 至chk_add之前的数据
	u_int8_t chk_xor;		 //包头异或和校验，内容包括type 至chk_xor之前的数据
};

u_int8_t net_packet_add(struct data_head *nhead)
{
	u_int8_t x = 0;
	u_int8_t *p = (u_int8_t *)nhead;
	int i;
	int n = offsetof(struct data_head, chk_add);

	for (i = 4; i < n; i++) {	// 远离unuse
		x += p[i];
	}
	return x;
}

u_int8_t net_packet_xor(struct data_head *nhead)
{
	u_int8_t x = 0;
	u_int8_t *p = (u_int8_t *)nhead;
	int i;
	int n = offsetof(struct data_head, chk_xor);

	for (i = 4; i < n; i++) {	// 远离unuse
		x ^= p[i];
	}
	return x;
}

int net_packet_check_head(struct data_head *nhead)
{
	if (nhead->chk_add != net_packet_add(nhead)) {
		fprintf(logfile, "包头校验错误 add\n");
		return 0;
	}
	if (nhead->chk_xor != net_packet_xor(nhead)) {
		fprintf(logfile, "包头校验错误 xor\n");
		return 0;
	}
	return 1;
}

#define logtcp(s_ip, d_ip, th, fmt, ...) do { \
	fprintf(logfile, "%s:%d -> %s:%d: " fmt, s_ip, ntohs(th->source_port), d_ip, ntohs(th->dest_port), ##__VA_ARGS__);\
} while (0)

int parse_tcp_packet(IPV4_HDR *ih, TCP_HDR *th, const u_char *data, int data_size)
{
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = ih->ip_srcaddr;
	char *s_ip = inet_ntoa(source.sin_addr);

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = ih->ip_destaddr;
	char *d_ip = inet_ntoa(dest.sin_addr);

	int sd = -1;
	if (strcmp(client_ip, s_ip) == 0) {
		// client is src
		sd = 0;
	} else if (strcmp(client_ip, d_ip) == 0) {
		// client is dst
		sd = 1;
	} else {
		return -1;
	}
	if (th->syn) {
		logtcp(s_ip, d_ip, th, "发起连接\n");
		return 0;
	}
	if (th->rst) {
		logtcp(s_ip, d_ip, th, "重建连接\n");
		return 0;
	}
	if (th->fin) {
		logtcp(s_ip, d_ip, th, "释放连接\n");
		return 0;
	}
	if (data_size) {
		// 分析tcp数据
		logtcp(s_ip, d_ip, th, "收到数据 %d\n", data_size);
		if (sizeof(struct data_head) > data_size) {
			return 0;
		}
		struct data_head *nhead = (struct data_head *)data;
		if (net_packet_check_head(nhead)) {
			logtcp(s_ip, d_ip, th, "收到包头正常 type %d\n", nhead->type);
		}
	}
	return 0;
}

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm *ltime;
	char timestr[80];
	time_t local_tv_sec;

	/* 将时间戳转换成可识别的格式 */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%Y-%m-%d %H:%M:%S", ltime);
	//print pkt timestamp and pkt len
	//fprintf(logfile , "\nNext Packet : %ld:%ld (Packet Length : %ld bytes) " , header->ts.tv_sec, header->ts.tv_usec, header->len);
	fprintf(logfile, "\nNext Packet : %s.%ld (Packet Length : %ld bytes) ", timestr, header->ts.tv_usec / 1000, header->len);
	ProcessPacket(pkt_data, header->caplen);
	return;
}

int main()
{
	u_int i, res, inum;
	char errbuf[PCAP_ERRBUF_SIZE];
	char buffer[100];
	u_char *pkt_data;
	time_t seconds;
	struct tm tbreak;
	pcap_if_t *alldevs, *d;
	pcap_t *fp;
	struct pcap_pkthdr *header;

	fopen_s(&logfile, "log.txt", "w");

	if (logfile == NULL)
	{
		printf("Unable to create file.");
	}

	/* The user didn't provide a packet source: Retrieve the local device list */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
		return -1;
	}

	i = 0;
	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s\n    ", ++i, d->name);

		if (d->description)
		{
			printf(" (%s)\n", d->description);
		}
		else
		{
			printf(" (No description available)\n");
		}
	}

	if (i == 0)
	{
		fprintf(stderr, "No interfaces found! Exiting.\n");
		return -1;
	}

	printf("Enter the interface number you would like to sniff : ");
	scanf_s("%d", &inum);

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* Open the device */
	if ((fp = pcap_open(d->name,
		65536 /*snaplen*/,
		PCAP_OPENFLAG_PROMISCUOUS /*flags*/,
		1000 /*read timeout*/,
		NULL /* remote authentication */,
		errbuf)
		) == NULL)
	{
		fprintf(stderr, "\nError opening adapter\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* 释放设备列表 */
	pcap_freealldevs(alldevs);
	/* 开始捕捉 */
	pcap_loop(fp, 0, packet_handler, NULL);

	return 0;
}

void ProcessPacket(const u_char* Buffer, int Size)
{
	//Ethernet header
	ethhdr = (ETHER_HDR *)Buffer;
	++total;

	//Ip packets
	if (ntohs(ethhdr->type) == 0x0800)
	{
		//ip header
		iphdr = (IPV4_HDR *)(Buffer + sizeof(ETHER_HDR));

		switch (iphdr->ip_protocol) //Check the Protocol and do accordingly...
		{
		case 1: //ICMP Protocol
			icmp++;
			//PrintIcmpPacket(Buffer, Size);
			break;

		case 2: //IGMP Protocol
			igmp++;
			break;

		case 6: //TCP Protocol
			tcp++;
			PrintTcpPacket(Buffer, Size);
			break;

		case 17: //UDP Protocol
			udp++;
			//print_udp_packet(Buffer, Size);
			break;

		default: //Some Other Protocol like ARP etc.
			others++;
			break;
		}
	}

	printf("TCP : %d UDP : %d ICMP : %d IGMP : %d Others : %d Total : %d\r", tcp, udp, icmp, igmp, others, total);
}

/*
Print the Ethernet header
*/
void print_ethernet_header(const u_char* buffer)
{
	ETHER_HDR *eth = (ETHER_HDR *)buffer;

	fprintf(logfile, "\n");
	fprintf(logfile, "Ethernet Header\n");
	fprintf(logfile, " |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->dest[0], eth->dest[1], eth->dest[2], eth->dest[3], eth->dest[4], eth->dest[5]);
	fprintf(logfile, " |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->source[0], eth->source[1], eth->source[2], eth->source[3], eth->source[4], eth->source[5]);
	fprintf(logfile, " |-Protocol            : 0x%.4x \n", ntohs(eth->type));
}

/*
Print the IP header for IP packets
*/
void PrintIpHeader(const unsigned char* Buffer, int Size)
{
	int iphdrlen = 0;

	iphdr = (IPV4_HDR *)(Buffer + sizeof(ETHER_HDR));
	iphdrlen = iphdr->ip_header_len * 4;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iphdr->ip_srcaddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iphdr->ip_destaddr;

	print_ethernet_header(Buffer);

	fprintf(logfile, "\n");
	fprintf(logfile, "IP Header\n");
	fprintf(logfile, " |-IP Version : %d\n", (unsigned int)iphdr->ip_version);
	fprintf(logfile, " |-IP Header Length : %d DWORDS or %d Bytes\n", (unsigned int)iphdr->ip_header_len, ((unsigned int)(iphdr->ip_header_len)) * 4);
	fprintf(logfile, " |-Type Of Service : %d\n", (unsigned int)iphdr->ip_tos);
	fprintf(logfile, " |-IP Total Length : %d Bytes(Size of Packet)\n", ntohs(iphdr->ip_total_length));
	fprintf(logfile, " |-Identification : %d\n", ntohs(iphdr->ip_id));
	fprintf(logfile, " |-Reserved ZERO Field : %d\n", (unsigned int)iphdr->ip_reserved_zero);
	fprintf(logfile, " |-Dont Fragment Field : %d\n", (unsigned int)iphdr->ip_dont_fragment);
	fprintf(logfile, " |-More Fragment Field : %d\n", (unsigned int)iphdr->ip_more_fragment);
	fprintf(logfile, " |-TTL : %d\n", (unsigned int)iphdr->ip_ttl);
	fprintf(logfile, " |-Protocol : %d\n", (unsigned int)iphdr->ip_protocol);
	fprintf(logfile, " |-Checksum : %d\n", ntohs(iphdr->ip_checksum));
	fprintf(logfile, " |-Source IP : %s\n", inet_ntoa(source.sin_addr));
	fprintf(logfile, " |-Destination IP : %s\n", inet_ntoa(dest.sin_addr));
}

/*
Print the TCP header for TCP packets
*/
void PrintTcpPacket(const u_char* Buffer, int Size)
{
	unsigned short iphdrlen;
	int header_size = 0, tcphdrlen, data_size;

	iphdr = (IPV4_HDR *)(Buffer + sizeof(ETHER_HDR));
	iphdrlen = iphdr->ip_header_len * 4;

	tcpheader = (TCP_HDR*)(Buffer + iphdrlen + sizeof(ETHER_HDR));
	tcphdrlen = tcpheader->data_offset * 4;

	data = (Buffer + sizeof(ETHER_HDR) + iphdrlen + tcphdrlen);
	data_size = (Size - sizeof(ETHER_HDR) - iphdrlen - tcphdrlen);


	fprintf(logfile, "\n\n***********************TCP Packet*************************\n");

	parse_tcp_packet(iphdr, tcpheader, data, data_size);
	PrintIpHeader(Buffer, Size);

	fprintf(logfile, "\n");
	fprintf(logfile, "TCP Header\n");
	fprintf(logfile, " |-Source Port : %u\n", ntohs(tcpheader->source_port));
	fprintf(logfile, " |-Destination Port : %u\n", ntohs(tcpheader->dest_port));
	fprintf(logfile, " |-Sequence Number : %u\n", ntohl(tcpheader->sequence));
	fprintf(logfile, " |-Acknowledge Number : %u\n", ntohl(tcpheader->acknowledge));
	fprintf(logfile, " |-Header Length : %d DWORDS or %d BYTES\n", (unsigned int)tcpheader->data_offset, (unsigned int)tcpheader->data_offset * 4);
	fprintf(logfile, " |-CWR Flag : %d\n", (unsigned int)tcpheader->cwr);
	fprintf(logfile, " |-ECN Flag : %d\n", (unsigned int)tcpheader->ecn);
	fprintf(logfile, " |-Urgent Flag : %d\n", (unsigned int)tcpheader->urg);
	fprintf(logfile, " |-Acknowledgement Flag : %d\n", (unsigned int)tcpheader->ack);
	fprintf(logfile, " |-Push Flag : %d\n", (unsigned int)tcpheader->psh);
	fprintf(logfile, " |-Reset Flag : %d\n", (unsigned int)tcpheader->rst);
	fprintf(logfile, " |-Synchronise Flag : %d\n", (unsigned int)tcpheader->syn);
	fprintf(logfile, " |-Finish Flag : %d\n", (unsigned int)tcpheader->fin);
	fprintf(logfile, " |-Window : %d\n", ntohs(tcpheader->window));
	fprintf(logfile, " |-Checksum : %d\n", ntohs(tcpheader->checksum));
	fprintf(logfile, " |-Urgent Pointer : %d\n", tcpheader->urgent_pointer);
	fprintf(logfile, "\n");
	fprintf(logfile, " DATA Dump ");
	fprintf(logfile, "\n");

	fprintf(logfile, "IP Header\n");
	PrintData((u_char*)iphdr, iphdrlen);

	fprintf(logfile, "TCP Header\n");
	PrintData((u_char*)tcpheader, tcphdrlen);

	fprintf(logfile, "Data Payload\n");
	PrintData(data, data_size);

	fprintf(logfile, "\n###########################################################\n");
}

/*
Print the UDP header for UDP packets
*/
void print_udp_packet(const u_char *Buffer, int Size)
{
	int iphdrlen = 0, data_size = 0;

	iphdr = (IPV4_HDR *)(Buffer + sizeof(ETHER_HDR));
	iphdrlen = iphdr->ip_header_len * 4;

	udpheader = (UDP_HDR*)(Buffer + iphdrlen + sizeof(ETHER_HDR));

	data = (Buffer + sizeof(ETHER_HDR) + iphdrlen + sizeof(UDP_HDR));
	data_size = (Size - sizeof(ETHER_HDR) - iphdrlen - sizeof(UDP_HDR));

	fprintf(logfile, "\n\n***********************UDP Packet*************************\n");

	PrintIpHeader(Buffer, Size);

	fprintf(logfile, "\nUDP Header\n");
	fprintf(logfile, " |-Source Port : %d\n", ntohs(udpheader->source_port));
	fprintf(logfile, " |-Destination Port : %d\n", ntohs(udpheader->dest_port));
	fprintf(logfile, " |-UDP Length : %d\n", ntohs(udpheader->udp_length));
	fprintf(logfile, " |-UDP Checksum : %d\n", ntohs(udpheader->udp_checksum));

	fprintf(logfile, "\n");

	fprintf(logfile, "IP Header\n");
	PrintData((u_char*)iphdr, iphdrlen);

	fprintf(logfile, "UDP Header\n");
	PrintData((u_char*)udpheader, sizeof(UDP_HDR));

	fprintf(logfile, "Data Payload\n");
	PrintData(data, data_size);

	fprintf(logfile, "\n###########################################################\n");
}

void PrintIcmpPacket(const u_char* Buffer, int Size)
{
	int iphdrlen = 0, icmphdrlen = 0, data_size = 0;

	iphdr = (IPV4_HDR *)(Buffer + sizeof(ETHER_HDR));
	iphdrlen = iphdr->ip_header_len * 4;

	icmpheader = (ICMP_HDR*)(Buffer + iphdrlen + sizeof(ETHER_HDR));

	data = (Buffer + sizeof(ETHER_HDR) + iphdrlen + sizeof(ICMP_HDR));
	data_size = (Size - sizeof(ETHER_HDR) - iphdrlen - sizeof(ICMP_HDR));

	fprintf(logfile, "\n\n***********************ICMP Packet*************************\n");
	PrintIpHeader(Buffer, Size);

	fprintf(logfile, "\n");

	fprintf(logfile, "ICMP Header\n");
	fprintf(logfile, " |-Type : %d", (unsigned int)(icmpheader->type));

	if ((unsigned int)(icmpheader->type) == 11)
	{
		fprintf(logfile, " (TTL Expired)\n");
	}
	else if ((unsigned int)(icmpheader->type) == 0)
	{
		fprintf(logfile, " (ICMP Echo Reply)\n");
	}

	fprintf(logfile, " |-Code : %d\n", (unsigned int)(icmpheader->code));
	fprintf(logfile, " |-Checksum : %d\n", ntohs(icmpheader->checksum));
	fprintf(logfile, " |-ID : %d\n", ntohs(icmpheader->id));
	fprintf(logfile, " |-Sequence : %d\n", ntohs(icmpheader->seq));
	fprintf(logfile, "\n");

	fprintf(logfile, "IP Header\n");
	PrintData((u_char*)iphdr, iphdrlen);

	fprintf(logfile, "ICMP Header\n");
	PrintData((u_char*)icmpheader, sizeof(ICMP_HDR));

	fprintf(logfile, "Data Payload\n");
	PrintData(data, data_size);

	fprintf(logfile, "\n###########################################################\n");
}

/*
Print the hex values of the data
*/
void PrintData(const u_char* data, int Size)
{
	unsigned char a, line[17], c;
	int j;

	//loop over each character and print
	for (i = 0; i < Size; i++)
	{
		c = data[i];

		//Print the hex value for every character , with a space
		fprintf(logfile, " %.2x", (unsigned int)c);

		//Add the character to data line
		a = (c >= 32 && c <= 128) ? (unsigned char)c : '.';

		line[i % 16] = a;

		//if last character of a line , then print the line - 16 characters in 1 line
		if ((i != 0 && (i + 1) % 16 == 0) || i == Size - 1)
		{
			line[i % 16 + 1] = '\0';

			//print a big gap of 10 characters between hex and characters
			fprintf(logfile, "          ");

			//Print additional spaces for last lines which might be less than 16 characters in length
			for (j = strlen((char *)line); j < 16; j++)
			{
				fprintf(logfile, "   ");
			}

			fprintf(logfile, "%s \n", line);
		}
	}

	fprintf(logfile, "\n");
}
