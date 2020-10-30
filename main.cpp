#include <exception>

#include "Crack.h"

int main()
{
	std::unique_ptr<Crack> crack(new Crack);

	try
	{
		std::vector<char> Chars = { '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z', };

		crack->InitParam(50, 2000, true);
		crack->PasswdGenerate(Chars);
		crack->Stat();
	}
	catch (const std::runtime_error& ex)
	{
		std::cerr << ex.what();
	}
}
