#pragma once

#include <vector>
#include <future>
//#include <atomic>
#include <mutex>

#include "File.h"
#include "Crypt.h"


class Crack
{
public:
	Crack();
	~Crack();

	void Encrypt();
	
	bool ThreadManager();
	bool PasswdLoop(std::vector<std::string> passwd);

	bool PasswdGenerate(const std::vector<char> Chars);
	void PasswdToFile();

	void InitParam(const int count, const int size, bool log);
	void Stat();

private:

	void BufFileData();
	bool Decrypt();

	File* m_file;
	Crypt* m_crypt;

	std::vector<unsigned char> m_chipherText;
	std::vector<unsigned char> m_hash;

	std::mutex m_lock;

	int m_threadCount;
	int m_passwdVectorSize;
	bool m_log;

	std::vector<std::future <bool>> m_thread;
	bool m_threadExit = false;
	std::vector<std::string> m_passwd;

	std::vector<std::string> m_verifiPasswd;
	std::string m_findingPasswd;

};

