/*
 * =====================================================================================
 *
 *       Filename:  packet-sniffer.h
 *
 *    Description:  项目所需头文件
 *
 *        Version:  1.0
 *        Created:  2014年02月27日 14时03分56秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Hurley (LiuHuan), liuhuan1992@gmail.com
 *        Company:  Class 1107 of Computer Science and Technology
 *
 * =====================================================================================
 */

#ifndef PACKET_SNIFFER_H_
#define PACKET_SNIFFER_H_

#define PS_DEBUG

#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifndef __cplusplus
	typedef enum {false, true} bool;
#endif

// 套结字接收缓冲区大小
#define RECV_BUF_SIZE 4096

typedef enum {
	protocol_all = ETH_P_ALL,
	protocol_ip = ETH_P_IP,
	protocol_ipv6 = ETH_P_IPV6,
	protocol_arp = ETH_P_ARP,
	protocol_rarp = ETH_P_RARP
} protocol_t;

void ps_debug(char *debug_info);

void print_usage();

// 初始化捕获套结字
int init_socket(char *net_name, protocol_t proto_type, bool is_promise);

// 销毁捕获套结字
void drop_socket(int conn_fd, char *net_name);

// 捕获数据包一次
void capture_socket_once(int conn_fd, void (*call_back_func)(const uint8_t *, int));

// 捕获数据包
void capture_socket(int conn_fd, void (*call_back_func)(const uint8_t *, int));

// 协议解析函数
void proto_parse(const uint8_t *proto_buf, int length);

#endif 	// PACKET_SNIFFER_H_

