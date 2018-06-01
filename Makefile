all: bin/mtufixer

bin:
	mkdir -p bin

bin/mtufixer: bin src/mtufixer.c
	gcc -O3 -Wall src/mtufixer.c -lpcap -o bin/mtufixer
