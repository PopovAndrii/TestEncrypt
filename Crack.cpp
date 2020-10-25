#include "Crack.h"

Crack::Crack()
{
	m_file = new File;
	m_crypt = new Crypt;
}

Crack::~Crack()
{
	delete m_file, m_crypt;
}

void Crack::BufFileData(std::vector<unsigned char>& chipherText, std::vector<unsigned char>& hash1)
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

std::string Crack::PasswdLoop(
	std::vector<std::string> passwd,
	std::vector<unsigned char> chipherText,
	std::vector<unsigned char> hash
)
{
	for (auto it = passwd.begin(); it != passwd.end(); ++it)
	{
		if (m_exitTread)
		{
			std::cout << " exit\n";
			return std::string();
		}

		m_crypt->PasswordToKey(*it);

		if (Decrypt(chipherText, hash))
		{
			m_exitTread = true;
			return *it;
		}
	}
	return std::string();
}

bool Crack::PasswdGenerate(std::vector<char> Chars)
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

			int vectorSize = 8000;
			if (pass.size() == vectorSize)
			{
				// tread.emplace_back(std::async(&Crack::PasswdLoop, this, pass, chipherText, hash1, std::ref(*m_file), std::ref(*m_crypt)));  :)
				tread.emplace_back(std::async(&Crack::PasswdLoop, this, pass, chipherText, hash1));

				int numberThreads = 16;
				if (tread.size() == numberThreads)
				{
					std::cout << "\nThreads(" << numberThreads << ") Vector Size(" << vectorSize << "):";

					for (int t = 0; t != numberThreads; ++t)
					{
						for (std::string s, c = "."; std::future_status::timeout == tread[t].wait_for(std::chrono::milliseconds(2)); )
						{
							std::cout << (c += s);
						}
						
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
