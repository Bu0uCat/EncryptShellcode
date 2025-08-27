#pragma once

#include <Windows.h>
#include <stdio.h>
#include <time.h>

#define KEYSIZE 32
#define IVSIZE 16

struct MyStruct {
	SIZE_T BytesNumber; // number of bytes read from the file 
	PVOID pShell;       // pointer to the shellcode read (here it is not appended) 
	/*PVOID pNewShell;    // pointer to the shellcode (appended)
	SIZE_T FinalSize;   // the size of the new appended shellcode
	HANDLE hFile;		// handle to the file created  */
};

struct MyStruct PayloadData = { 0 };

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//	Function Used To Read The Shellcode.bin File, Save the size of the shellcode and the Pointer To its Buffer in our struct.
BOOL ReadBinFile(char* FileInput) {
	HANDLE hFile;
	DWORD FileSize, lpNumberOfBytesRead;
	BOOL Succ;
	PVOID DllBytes;
	hFile = CreateFileA(FileInput, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_READONLY, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileA Failed With Error: [%d]\n", GetLastError());
		return FALSE;
	}
	FileSize = GetFileSize(hFile, NULL);
	DllBytes = malloc((SIZE_T)FileSize);
	Succ = ReadFile(hFile, DllBytes, FileSize, &lpNumberOfBytesRead, NULL);
	if (!Succ) {
		printf("[!] ReadFile Failed With Error: %d\n", GetLastError());
		return FALSE;
	}
	PayloadData.BytesNumber = (SIZE_T)lpNumberOfBytesRead;
	PayloadData.pShell = DllBytes;
	CloseHandle(hFile);
	return TRUE;
}
VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size) {

	printf("unsigned char %s[] = {", Name);

	int i = 0;
	for (; i < Size; i++) {
		if (i % 16 == 0)
			printf("\n\t");

		if (i < Size - 1) {
			printf("0x%0.2X, ", Data[i]);
		}
		else {
			printf("0x%0.2X ", Data[i]);
		}
	}
	printf("};\n\n\n");

}


/*AES*/
VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size);
VOID GenerateRandomBytes(PBYTE pByte, SIZE_T sSize);
BOOL PaddBuffer(IN PBYTE InputBuffer, IN SIZE_T InputBufferSize, OUT PBYTE* OutputPaddedBuffer, OUT SIZE_T* OutputPaddedSize) {

	PBYTE	PaddedBuffer = NULL;
	SIZE_T	PaddedSize = NULL;

	// 计算最接近的 16 的倍数，并将其保存到 PaddedSize
	PaddedSize = InputBufferSize + 16 - (InputBufferSize % 16);
	// 分配 “PaddedSize” 大小的缓冲区
	PaddedBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, PaddedSize);
	if (!PaddedBuffer) {
		return FALSE;
	}
	// 清除已分配的缓冲区
	ZeroMemory(PaddedBuffer, PaddedSize);
	// 将旧缓冲区复制到新填充缓冲区
	memcpy(PaddedBuffer, InputBuffer, InputBufferSize);
	// 保存结果：
	*OutputPaddedBuffer = PaddedBuffer;
	*OutputPaddedSize = PaddedSize;

	return TRUE;
}

BOOL AESencode(PBYTE Data, SIZE_T DataSize) {
	struct AES_ctx ctx;

	BYTE pKey[KEYSIZE];             // KEYSIZE 为 32 个字节
	BYTE pIv[IVSIZE];              // IVSIZE 为 16 个字节

	srand((unsigned int)time(NULL));                  // 生成密钥的种子
	GenerateRandomBytes(pKey, KEYSIZE); // 生成密钥字节

	srand((unsigned int)time(NULL) ^ pKey[0]);     // 生成 IV 的种子。使用密钥的第一个字节来增加随机性。
	GenerateRandomBytes(pIv, IVSIZE); // 生成 IV

	// 在控制台上打印密钥和 IV
	PrintHexData("pKey", pKey, KEYSIZE);
	PrintHexData("pIv", pIv, IVSIZE);

	// 初始化 Tiny-AES 库
	AES_init_ctx_iv(&ctx, pKey, pIv);

	// 初始化变量，用于在需要填充的情况下保存新的缓冲区基地址及其大小
	PBYTE	PaddedBuffer = NULL;
	SIZE_T	PAddedSize = NULL;

	// 根据需要填充缓冲区
	if (DataSize % 16 != 0) {
		PaddBuffer(Data, DataSize, &PaddedBuffer, &PAddedSize);
		// 加密已填充的缓冲区
		AES_CBC_encrypt_buffer(&ctx, PaddedBuffer, PAddedSize);
		// 在控制台上打印加密后的缓冲区
		PrintHexData("AESshellcode", PaddedBuffer, PAddedSize);
	}
	// 无需填充，直接加密 'Data'
	else {
		AES_CBC_encrypt_buffer(&ctx, Data, DataSize);
		// 在控制台上打印加密后的缓冲区
		PrintHexData("AESshellcode", Data, DataSize);
	}
	// 如果有必要，释放 PaddedBuffer
	if (PaddedBuffer != NULL) {
		HeapFree(GetProcessHeap(), 0, PaddedBuffer);
	}
	system("PAUSE");
	return TRUE;
}

VOID GenerateRandomBytes(PBYTE pByte, SIZE_T sSize) {

	int i = 0;
	for (; i < sSize; i++) {
		pByte[i] = (BYTE)rand() % 0xFF;
	}

}

/*RC4*/
typedef NTSTATUS(WINAPI* _SystemFunction033)(
	struct ustring* memoryRegion,
	struct ustring* keyPointer);

struct ustring {
	DWORD Length;
	DWORD MaximumLength;
	PUCHAR Buffer;
} _data, key;

BOOL RC4encode(PBYTE Data, SIZE_T DataSize) {

	printf("[*] RC4 Shellcode Encrypter using Systemfunction032/033\n");

	_SystemFunction033 SystemFunction033 = (_SystemFunction033)GetProcAddress(LoadLibraryA("advapi32"), "SystemFunction033");

	BYTE pKey[KEYSIZE];

	srand((unsigned int)time(NULL));
	for (int i = 0; i < KEYSIZE; i++) {
		pKey[i] = (BYTE)(rand() % 256);
	}
	PrintHexData("RC4 Key", pKey, KEYSIZE);

	key.Buffer = (PUCHAR)(&pKey);
	key.Length = KEYSIZE;

	_data.Buffer = Data;
	_data.Length = (ULONG)DataSize;

	SystemFunction033(&_data, &key);

	PrintHexData("RC4shellcode", Data, DataSize);

	return TRUE;
}

/*XOR*/
BOOL XORencode(PBYTE Data, SIZE_T DataSize) {

	BYTE pKey[IVSIZE];

	srand((unsigned int)time(NULL));
	for (int i = 0; i < IVSIZE; i++) {
		pKey[i] = (BYTE)(rand() % 256);
	}
	PrintHexData("XOR Key", pKey, IVSIZE);

	for (SIZE_T i = 0; i < DataSize; i++) {
		// 使用密钥循环对数据进行 XOR 操作
		Data[i] ^= pKey[i % IVSIZE];
	}

	// 打印加密后的数据
	PrintHexData("XOR CipherText", Data, DataSize);

	return TRUE;
}