CC=gcc
CFLAGS=-I.

hellomake: ws.c sha1.c
	gcc ws.c  sha1.c  -O0 -g -o  ws  
clean: ws
	rm -rf ws
