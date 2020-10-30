#pragma once

#include <iostream>
#include <vector>
#include <fstream>
#include <filesystem>

namespace fs = std::filesystem;

class File
{

public:

	void ReadFile(const fs::path& filePath, std::vector<unsigned char>& buf);
	void WriteFile(const fs::path& filePath, const std::vector<unsigned char>& buf);
	void AppendToFile(const fs::path& filePath, const std::vector<unsigned char>& buf);

};

