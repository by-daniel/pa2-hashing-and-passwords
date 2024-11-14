all: pwcrack

pwcrack: pwcrack.c
	gcc -std=c11 -Wall -fsanitize=address -g pwcrack.c -o pwcrack -lcrypto

clean:
	rm -f pwcrack
