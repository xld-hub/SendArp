#include "StrToHex.h"
#include <iostream>
// using namespace std;

StrToHex::StrToHex(/* args */)
{
}

StrToHex::~StrToHex()
{
}

void StrToHex::Mac(char* Mac,unsigned char * ret)
{

	char* tempmac[7] = { 0 };
	char* buf = nullptr;
	const char *flag = ":";
	tempmac[0] = strtok_s(Mac, flag, &buf);

	int count = 0;
	while (tempmac[count] != NULL)
	{
		count++;
		tempmac[count] = strtok_s(NULL, flag, &buf);
	}

	for (size_t i = 0; i < 6; i++)
	{

		int num = 0;
		for (size_t j = 0; j < 2; j++)
		{
			int multi;
			if (j == 0)
			{
				multi = 16;
			}
			else
			{
				multi = 1;
			}
			switch (tempmac[i][j])
			{
			case 'a':
				num += 10 * multi;
				break;
			case 'b':
				num += 11 * multi;
				break;
			case 'c':
				num += 12 * multi;
				break;
			case 'd':
				num += 13 * multi;
				break;
			case 'e':
				num += 14 * multi;
				break;
			case 'f':
				num += 15 * multi;
				break;
			default:
				num += (tempmac[i][j] - '0') * multi;
				break;
			}
		}
		ret[i] = num;
	}

    
}
void StrToHex::IP(char* Ip,unsigned char * ret)
{
	char* retip[5] = { 0 };

	char* buf = nullptr;
	const char* flag = ".";
	retip[0] = strtok_s(Ip, flag, &buf);
	int i = 0;
	while (retip[i] != NULL)
	{
		i++;
		retip[i] = strtok_s(NULL, flag, &buf);
	}

	for (size_t i = 0; i < 4; i++)
	{
		ret[i] = atoi(retip[i]);
	}
}

// int main()
// {
//     //192.168.204.2
//     // geteway[0] = 0xc0;
// 	// geteway[1] = 0xa8;
// 	// geteway[2] = 0xcc;
// 	// geteway[3] = 0x2;
//     StrToHex strtohex;
//     unsigned char *ret;
//     char ip[] = { "192.168.204.2" };
//     unsigned char retip[4];
//     char mac[] = { "00:0c:29:c0:41:8a" };
//     unsigned char retmac[6];
//     strtohex.IP(ip,retip);
//     strtohex.Mac(mac,retmac);
//     
//     cout<<hex<<retip;
// }