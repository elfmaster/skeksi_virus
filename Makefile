all: virus
virus:
	gcc -O0 -g -fno-stack-protector -DDEBUG -c virus.c -fpic -mcmodel=small -o virus.o
	gcc -fno-stack-protector -nostdlib virus.o -o virus
clean:
	rm -f virus
