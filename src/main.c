/*
 * =====================================================================================
 *
 *       Filename:  main.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2014年02月27日 14时00分20秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Hurley (LiuHuan), liuhuan1992@gmail.com
 *        Company:  Class 1107 of Computer Science and Technology
 *
 * =====================================================================================
 */

#include "packet-sniffer.h"

int main(int argc, char *argv[])
{
	if (argc != 3 || strcmp(argv[1], "-i") != 0) {
		print_usage();
		exit(EXIT_SUCCESS);
	}

	int fd;
	
	if ((fd = init_socket(argv[2])) < 0) {
		exit(EXIT_FAILURE);
	}

	int i;
	for (i = 0; i < 5; ++i) {
		capture_socket_once(fd, proto_parse);
	}

	drop_socket(fd, argv[2]);

	return EXIT_SUCCESS;
}

