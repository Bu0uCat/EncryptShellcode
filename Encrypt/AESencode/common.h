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

	// ������ӽ��� 16 �ı����������䱣�浽 PaddedSize
	PaddedSize = InputBufferSize + 16 - (InputBufferSize % 16);
	// ���� ��PaddedSize�� ��С�Ļ�����
	PaddedBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, PaddedSize);
	if (!PaddedBuffer) {
		return FALSE;
	}
	// ����ѷ���Ļ�����
	ZeroMemory(PaddedBuffer, PaddedSize);
	// ���ɻ��������Ƶ�����仺����
	memcpy(PaddedBuffer, InputBuffer, InputBufferSize);
	// ��������
	*OutputPaddedBuffer = PaddedBuffer;
	*OutputPaddedSize = PaddedSize;

	return TRUE;
}

BOOL AESencode(PBYTE Data, SIZE_T DataSize) {
	struct AES_ctx ctx;

	BYTE pKey[KEYSIZE];             // KEYSIZE Ϊ 32 ���ֽ�
	BYTE pIv[IVSIZE];              // IVSIZE Ϊ 16 ���ֽ�

	srand((unsigned int)time(NULL));                  // ������Կ������
	GenerateRandomBytes(pKey, KEYSIZE); // ������Կ�ֽ�

	srand((unsigned int)time(NULL) ^ pKey[0]);     // ���� IV �����ӡ�ʹ����Կ�ĵ�һ���ֽ�����������ԡ�
	GenerateRandomBytes(pIv, IVSIZE); // ���� IV

	// �ڿ���̨�ϴ�ӡ��Կ�� IV
	PrintHexData("pKey", pKey, KEYSIZE);
	PrintHexData("pIv", pIv, IVSIZE);

	// ��ʼ�� Tiny-AES ��
	AES_init_ctx_iv(&ctx, pKey, pIv);

	// ��ʼ����������������Ҫ��������±����µĻ���������ַ�����С
	PBYTE	PaddedBuffer = NULL;
	SIZE_T	PAddedSize = NULL;

	// ������Ҫ��仺����
	if (DataSize % 16 != 0) {
		PaddBuffer(Data, DataSize, &PaddedBuffer, &PAddedSize);
		// ���������Ļ�����
		AES_CBC_encrypt_buffer(&ctx, PaddedBuffer, PAddedSize);
		// �ڿ���̨�ϴ�ӡ���ܺ�Ļ�����
		PrintHexData("AESshellcode", PaddedBuffer, PAddedSize);
	}
	// ������䣬ֱ�Ӽ��� 'Data'
	else {
		AES_CBC_encrypt_buffer(&ctx, Data, DataSize);
		// �ڿ���̨�ϴ�ӡ���ܺ�Ļ�����
		PrintHexData("AESshellcode", Data, DataSize);
	}
	// ����б�Ҫ���ͷ� PaddedBuffer
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
		// ʹ����Կѭ�������ݽ��� XOR ����
		Data[i] ^= pKey[i % IVSIZE];
	}

	// ��ӡ���ܺ������
	PrintHexData("XOR CipherText", Data, DataSize);

	return TRUE;
}