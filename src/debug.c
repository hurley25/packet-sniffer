/*
 * =====================================================================================
 *
 *       Filename:  debug.c
 *
 *    Description:  调试相关函数
 *
 *        Version:  1.0
 *        Created:  2014年02月27日 14时37分46秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Hurley (LiuHuan), liuhuan1992@gmail.com
 *        Company:  Class 1107 of Computer Science and Technology
 *
 * =====================================================================================
 */

#include "packet-sniffer.h"

void ps_debug(char *debug_info)
{
#ifdef PS_DEBUG
	perror(debug_info);
#else
	// TODO
#endif
}

