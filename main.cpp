#include <string>
#include <vector>
//#include <fstream>
#include <exception>
#include <iostream>
#include <future>

#include "File.h"
#include "Crypt.h"
//#include "Crack.h"

void bufFileData(std::vector<unsigned char>& chipherText, std::vector<unsigned char>& hash1, File& file, Crypt& crypt)
{
	file.ReadFile("./text/chipher_text_brute_force", chipherText);

	crypt.CatTextAndHash(chipherText, hash1);
}

bool Decrypt(std::vector<unsigned char>& chipherText1, std::vector<unsigned char>& hash1, File& file, Crypt& crypt)
{
	std::vector<unsigned char> plainText;
	if (!crypt.DecryptAes(chipherText1, plainText)) {
		return false;
	}

	std::vector<unsigned char> hash2;
	crypt.CalculateHash(plainText, hash2);

	if (hash1 == hash2) {
		std::cout << "\n Check summ is correct. Write..." << std::endl;
		file.WriteFile("./text/final_text", plainText);
	}
	else {
		return false;
	}

	return true;
}

void Encrypt(File& file, Crypt& crypt)
{
	std::vector<unsigned char> plainText;
	file.ReadFile("./text/plain_text", plainText);

	std::vector<unsigned char> hash;
	crypt.CalculateHash(plainText, hash);

	std::vector<unsigned char> chipherText;
	crypt.EncryptAes(plainText, chipherText);

	file.WriteFile("./text/chipher_text1", chipherText);

	file.AppendToFile("./text/chipher_text1", hash);
}

std::string PasswdLoop(
	std::vector<std::string> passwd, 
	std::vector<unsigned char> chipherText,
	std::vector<unsigned char> hash,
	File file,
	Crypt crypt)
{
	for (auto it = passwd.begin(); it != passwd.end(); ++it)
	{
		crypt.PasswordToKey(*it);

		if (Decrypt(chipherText, hash, file, crypt))
		{
			return *it;
		}
	}
	return "";
}

bool Crack(std::vector<char> Chars, File& file, Crypt& crypt)
{
	std::vector<unsigned char> chipherText;
	std::vector<unsigned char> hash1;
	bufFileData(chipherText, hash1, file, crypt);

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
				tread.emplace_back(std::async(PasswdLoop, pass, chipherText, hash1, file, crypt));

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
	std::unique_ptr<Crypt> crypt(new Crypt);

	std::unique_ptr<File> file(new File);

	//std::string pass = "3"; // [k5fq]
	try
	{
		//PasswordToKey(pass);
		//Encrypt(*file, *crypt);

		std::vector<char> Chars = { '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z', };

		Crack(Chars, *file, *crypt);

	}
	catch (const std::runtime_error& ex)
	{
		std::cerr << ex.what();
	}


}
