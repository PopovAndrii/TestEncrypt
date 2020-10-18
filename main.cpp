#include <string>
#include <vector>
#include <fstream>
#include <exception>
#include <iostream>
#include <future>
//#include <mutex>
//#include <Windows.h>

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
		std::cout << "dgst\n"; // fix
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
	if (!EVP_EncryptUpdate(ctx, &chipherTextBuf[0], &chipherTextSize, &plainText[0], plainText.size())) {
		EVP_CIPHER_CTX_free(ctx);
		throw std::runtime_error("Encrypt error");
	}

	int lastPartLen = 0;
	if (!EVP_EncryptFinal_ex(ctx, &chipherTextBuf[0] + chipherTextSize, &lastPartLen)) {
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
	if (!EVP_DecryptUpdate(ctx, &chipherTextBuf[0], &chipherTextSize, &plainText[0], plainText.size())) {
		EVP_CIPHER_CTX_free(ctx);
		//throw std::runtime_error("Decrypt error");
	}

	int lastPartLen = 0;
	if (!EVP_DecryptFinal_ex(ctx, &chipherTextBuf[0] + chipherTextSize, &lastPartLen)) {
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

void CatTextAndHash(std::vector<unsigned char>& data, std::vector<unsigned char>& hash)
{
	int sizeData = size(data);

	if (sizeData < SHA256_DIGEST_LENGTH) {
		//throw std::runtime_error("Corrupted file data");
	}

	int is = sizeData - SHA256_DIGEST_LENGTH;
	for (int i = 0; is != sizeData; ++is, ++i) {
		hash.push_back(data[is]);
	}

	data.resize(sizeData - SHA256_DIGEST_LENGTH);
}

void bufFileData(std::vector<unsigned char>& chipherText, std::vector<unsigned char>& hash1)
{
	std::unique_ptr<File> file(new File);

	file->ReadFile("./text/chipher_text_brute_force", chipherText);

	CatTextAndHash(chipherText, hash1);
}

bool Decrypt(std::vector<unsigned char>& chipherText1, std::vector<unsigned char>& hash1)
{
	std::unique_ptr<File> file(new File);

	std::vector<unsigned char> plainText;
	if (!DecryptAes(chipherText1, plainText)) {
		return false;
	}

	std::vector<unsigned char> hash2;
	CalculateHash(plainText, hash2);

	if (hash1 == hash2) {
		std::cout << "\n Check summ is correct. Write..." << std::endl;
		file->WriteFile("./text/final_text", plainText);
	}
	else {
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

	file->WriteFile("./text/chipher_text1", chipherText);

	file->AppendToFile("./text/chipher_text1", hash);
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
	return "";
}

bool Crack(std::vector<char> Chars)
{
	std::vector<unsigned char> chipherText;
	std::vector<unsigned char> hash1;
	bufFileData(chipherText, hash1);

	std::vector<std::future <std::string>> tread;
	std::vector<std::string> pass;

	int n = Chars.size();
	int i = 0;

	bool itaratePasswd = true;
	while (itaratePasswd)
	{
		++i;
		int N = 1;
		for (int j = 0; j < i; ++j) N *= n;
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

			int vectorSize = 5000;
			if (pass.size() == vectorSize)
			{
				tread.emplace_back(std::async(PasswdLoop, pass, chipherText, hash1));

				int numberTreds = 16;
				if (tread.size() == numberTreds)
				{
					std::cout << "\nTreds("<< numberTreds << ") Vector Size(" << vectorSize << "):";
					
					for (int t = 0; t != numberTreds; ++t)
					{
						for (std::string s, c = "."; std::future_status::timeout == tread[t].wait_for(std::chrono::milliseconds(1)); )
						{
							std::cout << (c += s);
						}
					}

					for (int t = 0; t != numberTreds; ++t)
					{
						std::string findingPasswd = tread[t].get();
						if (!findingPasswd.empty())
						{
							std::cout << findingPasswd << std::endl;
							itaratePasswd = false; // fix
							
							return true;
						}
					}
					tread.clear();
				}
				pass.clear();
			}
			//std::cout << " Cracked password: " << crack << std::endl;
		}
	}
	return true;
}

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
		//PasswordToKey(pass);
		//Encrypt();

		//std::vector<char> Chars = { '5','f','k','q','r','s','t','u','v','w','x','y','z', };
		std::vector<char> Chars = { '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z', };

		Crack(Chars);

		//std::unique_ptr<File> file(new File);
		//file->WriteFile("./text/passwdChecked.txt", passwdChecked); // append to file!


	}
	catch (const std::runtime_error& ex)
	{
		std::cerr << ex.what();
	}


}
