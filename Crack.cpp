#include "Crack.h"

Crack::Crack(File* file, Crypt* crypt)
{
	m_file = file;
	m_crypt = crypt;
}

void Crack::bufFileData(std::vector<unsigned char>& chipherText, std::vector<unsigned char>& hash1)
{
	m_file->ReadFile("./text/chipher_text_brute_force", chipherText);

	m_crypt->CatTextAndHash(chipherText, hash1);
}

bool Crack::Decrypt(std::vector<unsigned char>& chipherText1, std::vector<unsigned char>& hash1)
{
	std::vector<unsigned char> plainText;
	if (!m_crypt->DecryptAes(chipherText1, plainText))
	{
		return false;
	}

	std::vector<unsigned char> hash2;
	m_crypt->CalculateHash(plainText, hash2);

	if (hash1 == hash2) {
		std::cout << "\n Check summ is correct. Write..." << std::endl;
		m_file->WriteFile("./text/final_text", plainText);
	}
	else
	{
		return false;
	}

	return true;
}

void Crack::Encrypt()
{
	std::vector<unsigned char> plainText;
	m_file->ReadFile("./text/plain_text", plainText);

	std::vector<unsigned char> hash;
	m_crypt->CalculateHash(plainText, hash);

	std::vector<unsigned char> chipherText;
	m_crypt->EncryptAes(plainText, chipherText);

	m_file->WriteFile("./text/chipher_text1", chipherText);

	m_file->AppendToFile("./text/chipher_text1", hash);
}

std::string Crack::PasswdLoop1(std::vector<std::string> passwd, std::vector<unsigned char> chipherText, std::vector<unsigned char> hash)
{
	for (auto it = passwd.begin(); it != passwd.end(); ++it)
	{
		m_crypt->PasswordToKey(*it);

		if (Decrypt(chipherText, hash))
		{
			return *it;
		}
	}
	return std::string(); // ""
}
