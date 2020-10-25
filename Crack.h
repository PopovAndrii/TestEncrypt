#pragma once

#include <vector>
#include <future>

#include "File.h"
#include "Crypt.h"


class Crack
{
public:
	Crack();
	~Crack();

	void Encrypt();
	
	std::string PasswdLoop(
		std::vector<std::string> passwd,
		std::vector<unsigned char> chipherText,
		std::vector<unsigned char> hash
	);

	bool PasswdGenerate(std::vector<char> Chars);


private:

	void BufFileData(std::vector<unsigned char>& chipherText, std::vector<unsigned char>& hash1);
	bool Decrypt(std::vector<unsigned char>& chipherText1, std::vector<unsigned char>& hash1);

	File* m_file;
	Crypt* m_crypt;

	bool m_exitTread = false;
};

