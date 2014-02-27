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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>

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

void ps_debug(char *debug_info);

void print_usage();

// 设置/取消网卡的混杂模式
bool set_network_promise(int conn_fd, char *net_name, bool choose);

// 初始化捕获套结字
int init_socket(char *net_name);

// 销毁捕获套结字
void drop_socket(int conn_fd, char *net_name);

// 捕获数据包一次
void capture_socket_once(int conn_fd, void (*func)(uint8_t *, int));

// 捕获数据包
void capture_socket(int conn_fd, void (*func)(uint8_t *, int));

// 协议解析函数
void proto_parse(uint8_t *buf, int size);

#endif 	// PACKET_SNIFFER_H_

