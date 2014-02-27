/*
 * =====================================================================================
 *
 *       Filename:  network.h
 *
 *    Description:  网络设置相关函数
 *
 *        Version:  1.0
 *        Created:  2014年02月27日 14时40分40秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Hurley (LiuHuan), liuhuan1992@gmail.com
 *        Company:  Class 1107 of Computer Science and Technology
 *
 * =====================================================================================
 */

#include "packet-sniffer.h"

// 设置/取消网卡的混杂模式
bool set_network_promise(int conn_fd, char *net_name, bool choose)
{
	struct ifreq ifr;
	bzero(&ifr, sizeof(ifr));
	
	assert(net_name != NULL);
	strcpy(ifr.ifr_name, net_name);

	if (ioctl(conn_fd, SIOCGIFFLAGS, &ifr) < 0) {
		ps_debug("set_network_promise:");
		return false;
	}

	if (choose) {
		ifr.ifr_flags |= IFF_PROMISC;
	} else {
		ifr.ifr_flags &= ~IFF_PROMISC;
	}

	if (ioctl(conn_fd, SIOCSIFFLAGS, &ifr) < 0) {
		ps_debug("set_network_promise:");
		return false;
	}

	return true;
}

// 初始化捕获套结字
int init_socket(char *net_name)
{
	int fd;
	
	if ((fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0 ) {
		ps_debug("init socket:");
		return -1;
	}

	if (!set_network_promise(fd, net_name, true)) {
		return -1;	
	}

	int recv_size = RECV_BUF_SIZE;
	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &recv_size, sizeof(int)) < 0) {
		ps_debug("init socket:");
		return -1;	
	}
	
	struct ifreq ifr;
	bzero(&ifr, sizeof(ifr));

	assert(net_name != NULL);
	strcpy(ifr.ifr_name, net_name);

	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
		ps_debug("init socket:");
		return -1;
	}
	
	struct sockaddr_ll sock_ll;

	bzero(&sock_ll, sizeof(sock_ll));
	sock_ll.sll_family = AF_PACKET;
	sock_ll.sll_ifindex = ifr.ifr_ifindex;
	sock_ll.sll_protocol = htons(ETH_P_ALL);
	
	if (bind(fd, (struct sockaddr *)&sock_ll, sizeof(sock_ll)) < 0) {
		ps_debug("bind:");
		return -1;
	}

	return fd;
}

// 销毁捕获套结字
void drop_socket(int conn_fd, char *net_name)
{
	set_network_promise(conn_fd, net_name, false);

	close(conn_fd);
}

// 捕获数据包一次
void capture_socket_once(int conn_fd, void (*func)(uint8_t *, int))
{
	uint8_t recv_buf[RECV_BUF_SIZE];
	socklen_t socklen;
	int size;

	bzero(recv_buf, RECV_BUF_SIZE);
	size = recvfrom(conn_fd, recv_buf, RECV_BUF_SIZE, 0, NULL, &socklen);
	func(recv_buf, size);
}

// 捕获数据包
void capture_socket(int conn_fd, void (*func)(uint8_t *, int))
{
	uint8_t recv_buf[RECV_BUF_SIZE];
	socklen_t socklen;
	int size;

	while (true) {
		bzero(recv_buf, RECV_BUF_SIZE);
		if ((size = recvfrom(conn_fd, recv_buf, RECV_BUF_SIZE, 0, NULL, &socklen)) < 0) {
			continue;
		}
		func(recv_buf, size);
	}
}

