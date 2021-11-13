.PHONY: all payload

all:
	cc -g server.c -o server

run: all
	./server 0.0.0.0 payload

debug: all
	gdb server

memcheck: all
	valgrind --leak-check=yes --track-origins=yes -s ./server --output output.bin 0.0.0.0 payload

payload:
	cc -fuse-ld=lld -Xlinker --image-base=0x0 -ffreestanding -nostdlib payload.c -o payload

clean:
	rm -rf server payload vgcore.* *.bin
