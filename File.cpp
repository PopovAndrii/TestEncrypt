#include "File.h"

void File::ReadFile(const fs::path& filePath, std::vector<unsigned char>& buf)
{
    std::basic_fstream<unsigned char> fileStream(filePath, std::ios::binary | std::fstream::in);
    if (!fileStream.is_open())
    {
        throw std::runtime_error("Can not open file");
    }

    buf.clear();
    buf.insert(buf.begin(), std::istreambuf_iterator<unsigned char>(fileStream), std::istreambuf_iterator<unsigned char>());

    if (!buf.size())
    {
        throw std::runtime_error("Empty file");
    }

    fileStream.close();
}

void File::WriteFile(const fs::path& filePath, const std::vector<unsigned char>& buf)
{
    std::basic_ofstream<unsigned char> fileStream(filePath, std::ios::binary);
    fileStream.write(&buf[0], buf.size());
    fileStream.close();
}

void File::AppendToFile(const fs::path& filePath, const std::vector<unsigned char>& buf)
{
    std::basic_ofstream<unsigned char> fileStream(filePath, std::ios::binary | std::ios::app);
    fileStream.write(&buf[0], buf.size());
    fileStream.close();
}

bool File::WriteFileString(const std::vector<std::string>& buf)
{
    std::ofstream fileStream(m_path, std::ios_base::app);
    if (!fileStream.is_open())
    {
        return false;
    }

    for (auto it = buf.cbegin(); it != buf.cend(); ++it)
    {
        fileStream << *it + "\n";
    }

    fileStream.close();

    return true;
}

bool File::TruncFile()
{
    std::ofstream fileStream(m_path, std::ios_base::trunc);
    if (!fileStream.is_open())
    {
        return false;
    }

    fileStream.close();

    return true;
}

void File::SetPath(const fs::path& filePath)
{
    m_path = filePath;
}