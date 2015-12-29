all: virus
virus:
	gcc -O0 -fno-stack-protector -c virus.c -fpic -mcmodel=small -o virus.o
	gcc -fno-stack-protector -nostdlib virus.o -o virus
clean:
	rm -f virus
