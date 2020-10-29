#include "Crypt.h"

Crypt::Crypt()
{
	OpenSSL_add_all_digests();
}

void Crypt::PasswordToKey(std::string& password)
{
	const EVP_MD* dgst = EVP_get_digestbyname("md5");
	if (!dgst)
	{
		//throw std::runtime_error("no such digest");
	}

	const unsigned char* salt = NULL;
	if (!EVP_BytesToKey(EVP_aes_128_cbc(), EVP_md5(), salt,
		reinterpret_cast<unsigned char*>(&password[0]),
		password.size(), 1, m_key, m_iv))
	{
		//throw std::runtime_error("EVP_BytesToKey failed");
	}
}

void Crypt::EncryptAes(const std::vector<unsigned char> plainText, std::vector<unsigned char>& chipherText)
{
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, m_key, m_iv))
	{
		throw std::runtime_error("EncryptInit error");
	}

	std::vector<unsigned char> chipherTextBuf(plainText.size() + AES_BLOCK_SIZE);
	int chipherTextSize = 0;
	if (!EVP_EncryptUpdate(ctx, &chipherTextBuf[0], &chipherTextSize, &plainText[0], plainText.size()))
	{
		EVP_CIPHER_CTX_free(ctx);
		throw std::runtime_error("Encrypt error");
	}

	int lastPartLen = 0;
	if (!EVP_EncryptFinal_ex(ctx, &chipherTextBuf[0] + chipherTextSize, &lastPartLen))
	{
		EVP_CIPHER_CTX_free(ctx);
		throw std::runtime_error("EncryptFinal error");
	}
	chipherTextSize += lastPartLen;
	chipherTextBuf.erase(chipherTextBuf.begin() + chipherTextSize, chipherTextBuf.end());

	chipherText.swap(chipherTextBuf);

	EVP_CIPHER_CTX_free(ctx);
}

bool Crypt::DecryptAes(const std::vector<unsigned char> plainText, std::vector<unsigned char>& chipherText)
{
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, m_key, m_iv))
	{
		//throw std::runtime_error("DecryptInit error");
	}

	std::vector<unsigned char> chipherTextBuf(plainText.size() + AES_BLOCK_SIZE);
	int chipherTextSize = 0;
	if (!EVP_DecryptUpdate(ctx, &chipherTextBuf[0], &chipherTextSize, &plainText[0], plainText.size()))
	{
		EVP_CIPHER_CTX_free(ctx);
		//throw std::runtime_error("Decrypt error");
	}

	int lastPartLen = 0;
	if (!EVP_DecryptFinal_ex(ctx, &chipherTextBuf[0] + chipherTextSize, &lastPartLen))
	{
		EVP_CIPHER_CTX_free(ctx);
		return false;
		//throw std::runtime_error("DecryptFinal error");
	}

	chipherTextSize += lastPartLen;
	chipherTextBuf.erase(chipherTextBuf.begin() + chipherTextSize, chipherTextBuf.end());

	chipherText.swap(chipherTextBuf);

	EVP_CIPHER_CTX_free(ctx);

	return true;
}

void Crypt::CalculateHash(const std::vector<unsigned char>& data, std::vector<unsigned char>& hash)
{
	std::vector<unsigned char> hashTmp(SHA256_DIGEST_LENGTH);

	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, &data[0], data.size());
	SHA256_Final(&hashTmp[0], &sha256);

	hash.swap(hashTmp);
}

void Crypt::CatTextAndHash(std::vector<unsigned char>& data, std::vector<unsigned char>& hash)
{
	int sizeData = size(data);

	if (sizeData < SHA256_DIGEST_LENGTH)
	{
		//throw std::runtime_error("Corrupted file data");
	}

	int is = sizeData - SHA256_DIGEST_LENGTH;

	for (int i = 0; is != sizeData; ++is, ++i)
	{
		hash.push_back(data[is]);
	}

	data.resize(sizeData - SHA256_DIGEST_LENGTH);
}
