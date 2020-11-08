#include "Crack.h"

Crack::Crack() :
	m_file(new File),
	m_crypt(new Crypt)
{
	BufFileData();
}

Crack::~Crack()
{
	if (m_file)
	{
		delete m_file;
	}

	if (m_crypt)
	{
		delete m_crypt;
	}
}

void Crack::BufFileData()
{
	m_file->ReadFile("./text/chipher_text_brute_force", m_chipherText);

	m_crypt->CatTextAndHash(m_chipherText, m_hash);
}

bool Crack::Decrypt()
{
	std::vector<unsigned char> plainText;
	if (!m_crypt->DecryptAes(m_chipherText, plainText))
	{
		return false;
	}

	std::vector<unsigned char> hash2;
	m_crypt->CalculateHash(plainText, hash2);

	if (m_hash == hash2)
	{
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

bool Crack::PasswdLoop(std::vector<std::string> passwd)
{
	for (auto it = passwd.begin(); it != passwd.end(); ++it)
	{
		if (m_threadExit)
		{
			return false;
		}

		m_crypt->PasswordToKey(*it);

		if (Decrypt())
		{
			m_threadExit = true;
			m_findingPasswd = *it;

			return true;
		}

		if (m_log) {
			{
				std::scoped_lock ul(m_lock);
				m_verifiPasswd.push_back(*it);
			}
		}
	}
	return false;
}

bool Crack::ThreadManager()
{
	m_thread.emplace_back(std::async(&Crack::PasswdLoop, this, std::move(m_passwd)));

	if (m_thread.size() == m_threadCount)
	{
		std::cout << ".";

		for (int t = 0; t != m_threadCount; ++t)
		{
			if (m_thread[t].get())
			{
				return true;
			}
		}
		m_thread.clear();
	}
	return false;
}

bool Crack::PasswdGenerate(const std::vector<char> Chars)
{
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
			std::string crack;
			for (int k = 0; k < i; ++k)
			{
				crack += Chars[j / K % n];
				K *= n;
			}

			m_passwd.push_back(std::move(crack));

			if (m_passwd.size() == m_passwdVectorSize)
			{
				if (ThreadManager())
				{
					return true;
				}
			}
		}
	}

	return true;
}

bool Crack::PasswdToFile()
{
	return m_file->WriteFileString("./text/log_passwd.txt", m_verifiPasswd);
}

void Crack::InitParam(int count, int size, bool log)
{
	m_threadCount = count;
	m_passwdVectorSize = size;
	m_log = log;
}

void Crack::Stat()
{
	std::cout << "\nDecrypted password: " << m_findingPasswd << std::endl;

	if (m_log)
	{
		std::cout << "Verified passwords: " << m_verifiPasswd.size() << std::endl;

		if (PasswdToFile())
		{
			std::cout << "Log created" << std::endl;
		}
	}
}