all: virus
virus:
	gcc -O0 -DANTIDEBUG -DINFECT_PLTGOT  -fno-stack-protector -c virus.c -fpic -o virus.o
#	gcc -g -DDEBUG -O0 -fno-stack-protector -c virus.c -fpic -mcmodel=small -o virus.o
	gcc -N -static -fno-stack-protector -nostdlib virus.o -o virus
	gcc -no-pie -Wl,-z,noseparate-code host.c -o host
	gcc -no-pie -Wl,-z,noseparate-code host.c -o host2
clean:
	rm -f virus
