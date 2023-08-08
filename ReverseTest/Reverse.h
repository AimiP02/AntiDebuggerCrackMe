#pragma once

#include "pch.h"

class Crypto {
public:
	Crypto(const char* Key) : Key(Key) {
		for (int i = 0; i < 256; i++) {
			S[i] = i;
		}

		for (int i = 0, j = 0; i < 256; i++) {
			j = (j + (S[i] & 0xFF) + ((BYTE)Key[i % strlen(Key)] & 0xFF)) % 256;
			std::swap(S[i], S[j]);
		}
	}
	~Crypto() = default;

	char* Encrypt(const char* data, int len);

public:
	const char* Key;

private:
	BYTE S[256];
};