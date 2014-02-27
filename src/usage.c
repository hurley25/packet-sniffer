/*
 * =====================================================================================
 *
 *       Filename:  usage.c
 *
 *    Description:  打印试用说明函数
 *
 *        Version:  1.0
 *        Created:  2014年02月27日 19时53分45秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Hurley (LiuHuan), liuhuan1992@gmail.com
 *        Company:  Class 1107 of Computer Science and Technology
 *
 * =====================================================================================
 */

#include <stdio.h>

void print_usage()
{
	printf("sniffer  一个混杂模式网卡数据包捕获和分析的小程序。\n\n"
		"使用方法：\n"
		"\tsniffer -i 网卡接口\n\n"
		"\t例如：sniffer -i eth0 或者 sniffer -i wlan0\n"
		);
}

