#pragma once

#include "pch.h"

class Crypto {
public:
	Crypto(unsigned char* Key, size_t len) : Key(Key) {
		for (int i = 0; i < 256; i++) {
			S[i] = i;
		}

		for (int i = 0, j = 0; i < 256; i++) {
			j = (j + S[i] + (BYTE)Key[i % len]) % 256;
			std::swap(S[i], S[j]);
		}
	}
	~Crypto() = default;

	unsigned char* Encrypt(unsigned char* data, size_t len);

public:
	unsigned char* Key;

private:
	unsigned char S[256];
};