#include <string>
#include <vector>
#include <fstream>
#include <exception>
#include <iostream>
#include <future>

#include "openssl/evp.h"
#include "openssl/aes.h"
#include "openssl/sha.h"

#include "File.h"

unsigned char key[EVP_MAX_KEY_LENGTH];
unsigned char iv[EVP_MAX_IV_LENGTH];

void PasswordToKey(std::string& password)
{
	const EVP_MD* dgst = EVP_get_digestbyname("md5");
	if (!dgst)
	{
		//throw std::runtime_error("no such digest");
	}

	const unsigned char* salt = NULL;
	if (!EVP_BytesToKey(EVP_aes_128_cbc(), EVP_md5(), salt,
		reinterpret_cast<unsigned char*>(&password[0]),
		password.size(), 1, key, iv))
	{
		//throw std::runtime_error("EVP_BytesToKey failed");
	}
}

void EncryptAes(const std::vector<unsigned char> plainText, std::vector<unsigned char>& chipherText)
{
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
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

bool DecryptAes(const std::vector<unsigned char> plainText, std::vector<unsigned char>& chipherText)
{
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
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

void CalculateHash(const std::vector<unsigned char>& data, std::vector<unsigned char>& hash)
{
	std::vector<unsigned char> hashTmp(SHA256_DIGEST_LENGTH);

	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, &data[0], data.size());
	SHA256_Final(&hashTmp[0], &sha256);

	hash.swap(hashTmp);
}

// Divide the text and checksum
void CatTextAndHash(std::vector<unsigned char>& data, std::vector<unsigned char>& hash)
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

// If you do not use this function, the calculation takes a long time.
void BufFileData(std::vector<unsigned char>& chipherText, std::vector<unsigned char>& hash1)
{
	std::unique_ptr<File> file(new File);

	file->ReadFile("./text/chipher_text_brute_force", chipherText);

	CatTextAndHash(chipherText, hash1);
}

bool Decrypt(std::vector<unsigned char>& chipherText, std::vector<unsigned char>& hash1)
{
	std::unique_ptr<File> file(new File);

	std::vector<unsigned char> plainText;
	if (!DecryptAes(chipherText, plainText))
	{
		return false;
	}

	std::vector<unsigned char> hash2;
	CalculateHash(plainText, hash2);

	if (hash1 == hash2)
	{
		std::cout << "\n Check summ is correct. Write..." << std::endl;
		file->WriteFile("./text/final_text", plainText);
	}
	else
	{
		return false;
	}

	return true;
}

void Encrypt()
{
	std::unique_ptr<File> file(new File);

	std::vector<unsigned char> plainText;
	file->ReadFile("./text/plain_text", plainText);

	std::vector<unsigned char> hash;
	CalculateHash(plainText, hash);

	std::vector<unsigned char> chipherText;
	EncryptAes(plainText, chipherText);

	file->WriteFile("./text/chipher_text", chipherText);

	file->AppendToFile("./text/chipher_text", hash);
}

std::string PasswdLoop(std::vector<std::string> passwd, std::vector<unsigned char> chipherText, std::vector<unsigned char> hash)
{
	for (auto it = passwd.begin(); it != passwd.end(); ++it)
	{
		PasswordToKey(*it);

		if (Decrypt(chipherText, hash))
		{
			return *it;
		}
	}
	return std::string();
}

bool Crack(std::vector<char> Chars, int numberTreads, int vectorSize)
{
	std::vector<unsigned char> chipherText;
	std::vector<unsigned char> hash1;
	BufFileData(chipherText, hash1);

	std::vector<std::future <std::string>> tread;
	std::vector<std::string> pass;

	int n = Chars.size();
	int i = 0;

	while (true)
	{
		++i;
		int N = 1;
		for (int j = 0; j < i; ++j)
		{
			N *= n;
		}
		for (int j = 0; j < N; ++j)
		{
			int K = 1;
			std::string crack = "";
			for (int k = 0; k < i; ++k)
			{
				crack += Chars[j / K % n];
				K *= n;
			}

			pass.push_back(crack);

			if (pass.size() == vectorSize)
			{
				tread.emplace_back(std::async(PasswdLoop, pass, chipherText, hash1));

				if (tread.size() == numberTreads)
				{
					std::cout << "\nTreads(" << numberTreads << ") Vector Size(" << vectorSize << "):";

					for (int t = 0; t != numberTreads; ++t)
					{
						for (std::string s, c = "."; std::future_status::timeout == tread[t].wait_for(std::chrono::milliseconds(1)); )
						{
							std::cout << (c += s);
						}
					}

					for (int t = 0; t != numberTreads; ++t)
					{
						std::string findingPasswd = tread[t].get();
						if (!findingPasswd.empty())
						{
							std::cout << findingPasswd << std::endl;
							return true;
						}
					}
					tread.clear();
				}
				pass.clear();
			}
		}
	}
	return true;
}

// The function is not used. Just to generate a dictionary
void GenereteRangeChars(std::vector<char>& Chars) {
	for (char c = '0'; c <= 'z'; c++) {
		if (isalpha(c) || isdigit(c)) {
			Chars.push_back(c);
		}
	}
}

int main()
{
	OpenSSL_add_all_digests();

	//std::string pass = "3"; // [k5fq]
	try
	{
		// !!!Warning!!! Rewrite plane_text new password
		//PasswordToKey(pass);
		//Encrypt();

		std::vector<char> Dictionary = { '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z', };

		// 16 Treads. 5000 VectorSize
		Crack(Dictionary, 16, 5000);

	}
	catch (const std::runtime_error& ex)
	{
		std::cerr << ex.what();
	}


}
