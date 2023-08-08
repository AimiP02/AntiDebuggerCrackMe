#include "pch.h"

#include "Reverse.h"

char* Crypto::Encrypt(const char* data, int len) {
	char* out = new char[len];

	int x = 0, y = 0;
	for (int i = 0; i < len; i++) {
		x = (x + 1) % 256;
		y = (y + S[x]) % 256;
		std::swap(S[x], S[y]);
		BYTE key = S[(S[x] + S[y]) % 256];
		out[i] = data[i] ^ key;
	}

	return out;
}