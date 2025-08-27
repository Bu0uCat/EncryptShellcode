#include <windows.h>
#include <stdio.h>
#include <iostream>

#include "aes.hpp"
#include "common.h"

#define AES 1000
#define RC4 2000
#define XOR 3000


int printUsage(char* MeLocation) {
	printf("[!] Usage: %s <payload file path> [Option*]\n", MeLocation);
	printf("[i] Option Can Be : \n");
	printf("\t[1] \"AES256\" || \"AES\" ::: Output an AES256-encrypted shellcode\n");
	printf("\t[2] \"RC4\" || \"ipv4\" ::: Output an RC4-encrypted shellcode\n");
	printf("\t[3] \"XOR\" || \"ipv6\" ::: Output an XOR-obfuscated shellcode\n");
	printf("[i] ");
	system("PAUSE");
	return -1;
}


void Logo() {

	// it probably wont be printed like that but ehh
	std::cout << R"(

 /$$$$$$$$                                                     /$$      /$$$$$$  /$$                 /$$ /$$                           /$$          
| $$_____/                                                    | $$     /$$__  $$| $$                | $$| $$                          | $$          
| $$       /$$$$$$$   /$$$$$$$  /$$$$$$  /$$   /$$  /$$$$$$  /$$$$$$  | $$  \__/| $$$$$$$   /$$$$$$ | $$| $$  /$$$$$$$  /$$$$$$   /$$$$$$$  /$$$$$$ 
| $$$$$   | $$__  $$ /$$_____/ /$$__  $$| $$  | $$ /$$__  $$|_  $$_/  |  $$$$$$ | $$__  $$ /$$__  $$| $$| $$ /$$_____/ /$$__  $$ /$$__  $$ /$$__  $$
| $$__/   | $$  \ $$| $$      | $$  \__/| $$  | $$| $$  \ $$  | $$     \____  $$| $$  \ $$| $$$$$$$$| $$| $$| $$      | $$  \ $$| $$  | $$| $$$$$$$$
| $$      | $$  | $$| $$      | $$      | $$  | $$| $$  | $$  | $$ /$$ /$$  \ $$| $$  | $$| $$_____/| $$| $$| $$      | $$  | $$| $$  | $$| $$_____/
| $$$$$$$$| $$  | $$|  $$$$$$$| $$      |  $$$$$$$| $$$$$$$/  |  $$$$/|  $$$$$$/| $$  | $$|  $$$$$$$| $$| $$|  $$$$$$$|  $$$$$$/|  $$$$$$$|  $$$$$$$
|________/|__/  |__/ \_______/|__/       \____  $$| $$____/    \___/   \______/ |__/  |__/ \_______/|__/|__/ \_______/ \______/  \_______/ \_______/
                                         /$$  | $$| $$                                                                                              
                                        |  $$$$$$/| $$                                                                                              
                                         \______/ |__/                                                                                              
)" << "\t\t\t\t\t\t\t\t\t\t\t\tBY Bu0uCat \n";
}

int main(int argc, char* argv[])
{
	int Type = 0;
	BOOL bSuccess = FALSE;
	Logo();
	if (argc != 3) {
		return printUsage(argv[0]);
	}
	if ((!ReadBinFile(argv[1])) || PayloadData.pShell == NULL || PayloadData.BytesNumber == NULL) {
		system("PAUSE");
		return -1;
	}
	if (strcmp(argv[2], "AES") == 0 || strcmp(argv[2], "aes") == 0) {
		Type = AES;
	}
	else if (strcmp(argv[2], "RC4") == 0 || strcmp(argv[2], "rc4") == 0) {
		Type = RC4;
	}
	else if (strcmp(argv[2], "xor") == 0 || strcmp(argv[2], "XOR") == 0) {
		Type = XOR;
	}
	switch (Type) {
	case AES:
		bSuccess = AESencode((PBYTE)PayloadData.pShell, PayloadData.BytesNumber);
		if (bSuccess == TRUE)
			break;
		else {
			printf("加密出错！");
			break;
		}
	case RC4:
		bSuccess = RC4encode((PBYTE)PayloadData.pShell, PayloadData.BytesNumber);
		if (bSuccess == TRUE)
			break;
		else {
			printf("加密出错！");
			break;
		}
	case XOR:
		bSuccess = XORencode((PBYTE)PayloadData.pShell, PayloadData.BytesNumber);
		if (bSuccess == TRUE)
			break;
		else {
			printf("加密出错！");
			break;
		}
	default:
		printf("[!] Unkown Error Occured %d \n", GetLastError());
		break;
	}
}