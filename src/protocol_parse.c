/*
 * =====================================================================================
 *
 *       Filename:  protocol_parse.c
 *
 *    Description:  协议解析
 *
 *        Version:  1.0
 *        Created:  2014年02月27日 19时36分32秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Hurley (LiuHuan), liuhuan1992@gmail.com
 *        Company:  Class 1107 of Computer Science and Technology
 *
 * =====================================================================================
 */

#include "packet-sniffer.h"

// 以太网帧的类型
const int eth_proto_id[] = {
			ETHERTYPE_PUP, ETHERTYPE_SPRITE, ETHERTYPE_IP, ETHERTYPE_ARP,
			ETHERTYPE_REVARP, ETHERTYPE_AT, ETHERTYPE_AARP, ETHERTYPE_VLAN,
			ETHERTYPE_IPX, ETHERTYPE_IPV6, ETHERTYPE_LOOPBACK
};

// 以太网帧类型对应的含义
const char eth_proto_str[][24] = { 
			"XEROX PUP", "SPRITE", "IP", "ARP",
			"RARP", "APPLE-PROTOCOL", "APPLE-ARP", "802.1Q",
			"IPX", "IPV6", "LOOPBACK" 
};

// 数据链路层解析
static void data_link_layer_parse(const uint8_t *proto_buf, int length);

// 网络层协议及其高层协议解析
static void ip_protocal_parse(const uint8_t *proto_buf, int length);

// TCP协议解析
static void tcp_protocal_parse(const uint8_t *proto_buf, int length);

// UDP协议解析
static void udp_protocal_parse(const uint8_t *proto_buf, int length);

// 协议解析函数
void proto_parse(const uint8_t *proto_buf, int length)
{
	data_link_layer_parse(proto_buf, length);
}

// 数据链路层解析
static void data_link_layer_parse(const uint8_t *proto_buf, int length)
{
	const struct ether_header *eth_head = (const struct ether_header *)proto_buf;
	
	printf("源Mac: ");

	int i;
	for(i = 0; i < ETHER_ADDR_LEN - 1; i++)  
	{  
		printf("%02x:", eth_head->ether_shost[i]);  
	}  
	printf("%02x ", eth_head->ether_shost[i]);
	
	printf("目标Mac: ");
	for(i = 0; i < ETHER_ADDR_LEN - 1; i++)  
	{  
		printf("%02x:", eth_head->ether_dhost[i]);  
	}  
	printf("%02x ", eth_head->ether_dhost[i]);

	const char *proto_type_str = "未知协议";
	uint16_t proto_type = ntohs(eth_head->ether_type);
	
	for (i = 0; i < sizeof(eth_proto_id)/sizeof(*eth_proto_id); ++i) {
		if (proto_type == eth_proto_id[i]) {
			proto_type_str = eth_proto_str[i];
			break;
		}
	}
	printf("协议类型: %s", proto_type_str);
	
	proto_buf += sizeof(struct ether_header);
	length -= sizeof(struct ether_header);

	// TODO 考虑映射为协议解析函数指针数组
	switch (ntohs(eth_head->ether_type)) {
	case ETHERTYPE_PUP:
		break;
	case ETHERTYPE_SPRITE:
		break;
	case ETHERTYPE_IP:
		ip_protocal_parse(proto_buf, length);
		break;
	case ETHERTYPE_ARP:
		break;
	case ETHERTYPE_REVARP:
		break;
	case ETHERTYPE_AT:
		break;
	case ETHERTYPE_AARP:
		break;
	case ETHERTYPE_VLAN:
		break;
	case ETHERTYPE_IPX:
		break;
	case ETHERTYPE_IPV6:
		break;
	case ETHERTYPE_LOOPBACK:
		break;
	default:
		break;
	}
	printf("\n");
}

// 网络层协议及其高层协议解析
static void ip_protocal_parse(const uint8_t *proto_buf, int length)
{
	const struct ip *ip_head = (const struct ip *)proto_buf;
	
	struct protoent *proto = getprotobynumber(ip_head->ip_p);
	assert(proto != NULL);
	printf("(%s) ", proto->p_name);  

	proto_buf += sizeof(struct ip);
	length -= sizeof(struct ip);

	// TODO 考虑映射为协议解析函数指针数组
	switch (ip_head->ip_p) {
	case IPPROTO_HOPOPTS:
		break;
	case IPPROTO_ICMP:
		break;
	case IPPROTO_IGMP:
		break;
	case IPPROTO_IPIP:
		break;
	case IPPROTO_TCP:
		tcp_protocal_parse(proto_buf, length);
		break;
	case IPPROTO_EGP:
		break;
	case IPPROTO_PUP:
		break;
	case IPPROTO_UDP:
		udp_protocal_parse(proto_buf, length);
		break;
	case IPPROTO_IDP:
		break;
	case IPPROTO_TP:
		break;
	case IPPROTO_DCCP:
		break;
	case IPPROTO_IPV6:
		break;
	case IPPROTO_ROUTING:
		break;
	case IPPROTO_FRAGMENT:
		break;
	case IPPROTO_RSVP:
		break;
	case IPPROTO_GRE:
		break;
	case IPPROTO_ESP:
		break;
	case IPPROTO_AH:
		break;
	case IPPROTO_ICMPV6:
		break;
	case IPPROTO_NONE:
		break;
	case IPPROTO_DSTOPTS:
		break;
	case IPPROTO_MTP:
		break;
	case IPPROTO_ENCAP:
		break;
	case IPPROTO_PIM:
		break;
	case IPPROTO_COMP:
		break;
	case IPPROTO_SCTP:
		break;
	case IPPROTO_UDPLITE:
		break;
	case IPPROTO_RAW:
		break;
	default:
		break;
	}
}

// TCP协议解析
static void tcp_protocal_parse(const uint8_t *proto_buf, int length)
{
	const struct ip *ip_head = (const struct ip *)(proto_buf - sizeof(struct ip));
	const struct tcphdr *tcp_head = (const struct tcphdr *)proto_buf;
	proto_buf += sizeof(struct tcphdr);
	length -= sizeof(struct tcphdr);

	printf("源IP: %s:%d ", inet_ntoa(ip_head->ip_src), ntohs(tcp_head->source));
	printf("目标IP: %s:%d ", inet_ntoa(ip_head->ip_dst), ntohs(tcp_head->dest));
	printf("剩余长度:%d ", length);
}

// UDP协议解析
static void udp_protocal_parse(const uint8_t *proto_buf, int length)
{
	const struct ip *ip_head = (const struct ip *)(proto_buf - sizeof(struct ip));
	const struct udphdr *udp_head = (const struct udphdr *)proto_buf;
	proto_buf += sizeof(struct tcphdr);
	length -= sizeof(struct tcphdr);

	printf("源IP: %s:%d ", inet_ntoa(ip_head->ip_src), ntohs(udp_head->source));
	printf("目标IP: %s:%d ", inet_ntoa(ip_head->ip_dst), ntohs(udp_head->dest));
	printf("剩余长度:%d ", length);
}

