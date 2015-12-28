all: virus
virus:
	gcc -O0 -g -fno-stack-protector -c syscall.c -fpic -mcmodel=small -o syscall.o
	gcc -O0 -g -fno-stack-protector -c libc.c -fpic -mcmodel=small -o libc.o
	gcc -O0 -g -fno-stack-protector -DDEBUG -c virus.c -fpic -mcmodel=small -o virus.o
	gcc -fno-stack-protector -nostdlib virus.o syscall.o libc.o -o virus
clean:
	rm -f virus
