all: virus
virus:
	gcc -g -DDEBUG -nostartfiles virus.c syscall.c libc.c malloc.c -o virus
clean:
	rm -f virus
