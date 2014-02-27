#!Makefile
#
# --------------------------------------------------------
#
#    Makefile  2014/2/27
#
# --------------------------------------------------------
#

C_SOURCES = $(shell find . -name "*.c")
C_OBJECTS = $(patsubst %.c, %.o, $(C_SOURCES))

CC = gcc

C_FLAGS = -c -g -Wall -Iinclude

all: $(C_OBJECTS) 
	@echo 链接 ...
	$(CC) $(C_OBJECTS) -o sniffer

.c.o:
	@echo 编译代码文件 $< ...
	$(CC) $(C_FLAGS) $< -o $@

.PHONY:clean
clean:
	@echo 清理临时文件
	$(RM) $(C_OBJECTS)

