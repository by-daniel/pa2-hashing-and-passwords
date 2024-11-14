#include <stdlib.h>
#include <stdio.h> 
#include <stdint.h>
#include <string.h>
#include <openssl/sha.h>
#include <ctype.h>

const int SHA_LENGTH = 32;

uint8_t hex_to_byte(unsigned char h1, unsigned char h2) {
	uint8_t x = 0;
	uint8_t y = 0;

	// Convert h1 to a decimal value
	if (h1 >= '0' && h1 <=  '9') {
		x += h1 - '0';
	}
	else if (h1 >= 'a' && h1 <= 'f') {
		x += h1 - 'a' + 10;
	}

	// Convert h2 to a decimal value
	if (h2 >= '0' && h2 <= '9') {
		y += h2 - '0';
	}
	else if (h2 >= 'a' && h2 <= 'f') {
		y += h2 - 'a' + 10;
	}

	// TODO: Determine what the function should return
	return (x << 4) | y;
}

void hexstr_to_hash(char hexstr[], unsigned char hash[32]) {
	for (int i = 0; i < 32; i++) {
		unsigned char byte = (hex_to_byte(hexstr[i*2], hexstr[i*2 + 1]));
		hash[i] = byte;
	}
}

int8_t check_password(char password[], unsigned char given_hash[32]) {
	unsigned char computed_hash[32];
	SHA256((unsigned char*)password, strlen(password), computed_hash);

	for (int i = 0; i < SHA_LENGTH; i++) {
		if (computed_hash[i] != given_hash[i]) {
			return 0;
		}
	}
	return 1;
}

int crack_password(char password[], unsigned char given_hash[]) {
	if (check_password(password, given_hash)) {
		return 1;
	}

	for (int i = 0; password[i] != '\0'; i++) {
		char original_char = password[i];
		if (isalpha(original_char)) {
			password[i] = toupper(original_char);
			if (check_password(password, given_hash)) {
				return 1;
			}
			password[i] = tolower(original_char);
			if (check_password(password, given_hash)) {
				return 1;
			}
		} else if (isdigit(original_char)) {
			for (char digit = '0'; digit <= '9'; digit++) {
				password[i] = digit;
				if (check_password(password, given_hash)) {
					return 1;
				}
			}
		}

		password[i] = original_char;
	}

	return 0;
}

int main(int argc, char **argv) {
	if (argc != 2) {
		printf("Bad input. Please try again.\n");
		return 1;
	}

	unsigned char given_hash[SHA_LENGTH];
	hexstr_to_hash(argv[1], given_hash);
	char password[256];
	int cracked = 0;

	while (fgets(password, sizeof(password), stdin)) {
		size_t len = strlen(password);
		if (password[len-1] == '\n') {
			password[len-1] = '\0';
		}

		if (check_password(password, given_hash) || crack_password(password, given_hash)) {
			printf("Found password: SHA256(%s) = %s\n", password, argv[1]);
			cracked = 1;
			break;
		}
	}

	if (!cracked) {
		printf("Did not find a matching password\n");
	}

	return 0;
}
