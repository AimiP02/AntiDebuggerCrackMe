#include "pch.h"
#include "Crypto.h"

unsigned char* Crypto::Encrypt(unsigned char* data, size_t len) {
	unsigned char* out = new unsigned char[len];
	memset(out, 0, len);

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