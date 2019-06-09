#
# Copyright (C) 2018 David C. Harrison - All Rights Reserved.
# You may not use, distribute, or modify this code without
# the express written permission of the copyright holder.
#

CFLAGS = -Wall #-fno-stack-protector -z execstack
LIBS = -lpthread
CC = gcc

all: server 

server: server.c http.c
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

clean:
	rm -f server 
