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

	Crack(const Crack& obj) = delete;
	Crack& operator=(Crack& obj) = delete;

	void Encrypt();
	
	bool ThreadManager();
	bool PasswdLoop(std::vector<std::string> passwd);
	bool WritePasswdLoop();

	bool PasswdGenerate(const std::vector<char> Chars);

	void InitParam(const int count, const int size, bool log);
	void Stat();

private:

	void BufFileData();
	bool Decrypt();

	File* m_file = nullptr;
	Crypt* m_crypt = nullptr;

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
	int m_verifiPasswdSize = 0;
	std::string m_findingPasswd;

};

