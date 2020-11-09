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
	
	bool WriteFileString(const std::vector<std::string>& buf);
	bool TruncFile();
	void SetPath(const fs::path& filePath);

private:
	fs::path m_path;
};

