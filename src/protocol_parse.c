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
			ETHERTYPE_PUP, 
			ETHERTYPE_SPRITE, 
			ETHERTYPE_IP, 
			ETHERTYPE_ARP,
			ETHERTYPE_REVARP,
			ETHERTYPE_AT,
			ETHERTYPE_AARP,
			ETHERTYPE_VLAN,
			ETHERTYPE_IPX,
			ETHERTYPE_IPV6,
			ETHERTYPE_LOOPBACK
		};

// 以太网帧类型对应的含义
const char eth_proto_str[][24] = { 
				"XEROX PUP",
				"SPRITE",
				"IP",
				"ARP",
				"RARP",
				"APPLE-PROTOCOL",
				"APPLE-ARP",
				"802.1Q",
				"IPX",
				"IPV6",
				"LOOPBACK" 
                                };

// 数据链路层解析
static void data_link_layer_parse(const struct ether_header *addr)   
{
	printf("源Mac地址: ");

	int i;
	for(i = 0; i < ETHER_ADDR_LEN - 1; i++)  
	{  
		printf("%02x:", addr->ether_shost[i]);  
	}  
	printf("%02x ", addr->ether_shost[i]);
	
	printf("目标Mac地址: ");
	for(i = 0; i < ETHER_ADDR_LEN - 1; i++)  
	{  
		printf("%02x:", addr->ether_dhost[i]);  
	}  
	printf("%02x ", addr->ether_dhost[i]);

	const char *proto_type_str = "未知协议";
	uint16_t proto_type = htons(addr->ether_type);
	
	for (i = 0; i < sizeof(eth_proto_id)/sizeof(*eth_proto_id); ++i) {
		if (proto_type == eth_proto_id[i]) {
			proto_type_str = eth_proto_str[i];
			break;
		}
	}
	printf("协议类型: %s", proto_type_str);
}

// IP协议及其高层协议解析
static void ip_protocal_parse(const struct ip *ip_head)
{
	struct protoent *proto = getprotobynumber(ip_head->ip_p);

	assert(proto != NULL);
	printf("(%s) ", proto->p_name);  
	printf("源IP: %-15s ", inet_ntoa(ip_head->ip_src));  
	printf("目标IP: %-15s ", inet_ntoa(ip_head->ip_dst));

	switch (ip_head->ip_p) {
	//case :
	default:
		break;
	}
}

// 协议解析函数
void proto_parse(const uint8_t *buf, int size)
{
	const uint8_t *proto_buf = buf;
	const struct ether_header *eth_head = (struct ether_header *)proto_buf;
	proto_buf += sizeof(struct ether_header);

	data_link_layer_parse(eth_head);

	const struct ip *ip_head = (struct ip *)proto_buf;

	switch (htons(eth_head->ether_type)) {
	case ETHERTYPE_IP:
		ip_protocal_parse(ip_head);
		break;
	// TODO
	//case ETHERTYPE_ARP:
	//	break;
	default:
		printf("高层协议暂未支持");
	}

	printf("\n");
}

