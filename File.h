#pragma once

#include <iostream>
#include <vector>
#include <fstream>

class File
{
public:

	void ReadFile(const std::string& filePath, std::vector<unsigned char>& buf);
	void WriteFile(const std::string& filePath, const std::vector<unsigned char>& buf);
	void AppendToFile(const std::string& filePath, const std::vector<unsigned char>& buf);

};

