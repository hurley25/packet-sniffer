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

static void data_link_layer_parse(const struct ether_header *addr)   
{
	int i;

	printf("from: ");
	for(i = 0; i < ETHER_ADDR_LEN - 1; i++)  
	{  
		printf("%02x:", addr->ether_shost[i]);  
	}  
	printf("%02x  ", addr->ether_shost[i]);
	
	printf("to: ");
	for(i = 0; i < ETHER_ADDR_LEN - 1; i++)  
	{  
		printf("%02x:", addr->ether_dhost[i]);  
	}  
	printf("%02x", addr->ether_dhost[i]);
}

// 协议解析函数
void proto_parse(uint8_t *buf, int size)
{
	struct ether_header *eth_head = (struct ether_header *)buf;
	data_link_layer_parse(eth_head);
	printf("\n");
}

