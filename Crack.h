#pragma once

#include <vector>
#include <future>

#include "File.h"
#include "Crypt.h"


class Crack
{
public:
	Crack(File* file, Crypt* crypt);

	void bufFileData(std::vector<unsigned char>& chipherText, std::vector<unsigned char>& hash1);
	bool Decrypt(std::vector<unsigned char>& chipherText1, std::vector<unsigned char>& hash1);
	void Encrypt();
	std::string PasswdLoop1(std::vector<std::string> passwd, std::vector<unsigned char> chipherText, std::vector<unsigned char> hash);


private:
	File* m_file;
	Crypt* m_crypt;
};

