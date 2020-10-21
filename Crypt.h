#pragma once
#include <string>
#include <iostream>
#include <vector>

#include "openssl/evp.h"
#include "openssl/aes.h"
#include "openssl/sha.h"

class Crypt
{
public:
	Crypt();

	void PasswordToKey(std::string& password);
	void EncryptAes(const std::vector<unsigned char> plainText, std::vector<unsigned char>& chipherText);
	bool DecryptAes(const std::vector<unsigned char> plainText, std::vector<unsigned char>& chipherText);
	void CalculateHash(const std::vector<unsigned char>& data, std::vector<unsigned char>& hash);
	void CatTextAndHash(std::vector<unsigned char>& data, std::vector<unsigned char>& hash);

private:

	unsigned char m_key[EVP_MAX_KEY_LENGTH];
	unsigned char m_iv[EVP_MAX_IV_LENGTH];
};

