all: virus
virus:
	gcc -O0 -g -c malloc.c -fpic -mcmodel=small -o malloc.o
	gcc -O0 -g -c syscall.c -fpic -mcmodel=small -o syscall.o
	gcc -O0 -g -c libc.c -fpic -mcmodel=small -o libc.o
	gcc -O0 -g -DDEBUG -c virus.c -fpic -mcmodel=small -o virus.o
	gcc -nostartfiles virus.o syscall.o libc.o malloc.o -o virus
clean:
	rm -f virus
