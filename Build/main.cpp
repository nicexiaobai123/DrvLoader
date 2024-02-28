#include <iostream>
using namespace std;

#define XOR_ENCODE_KEY 0xAB
#define MAX_LINE_LENGTH 40

// �ù����ǽ�PE�ļ�ת����һ��.hͷ�ļ�,������һ���ַ�����洢PE�Ķ�������
int main(int argc, char* args[], char** env)
{
	if (argc < 2)
	{
		cout << "��������,����: build.exe dll·��" << endl;
		return 1;
	}

	FILE* file = NULL;
	fopen_s(&file, args[1], "rb");
	if (!file)
	{
		cout << "�ļ�������" << endl;
		return 1;
	}

	// ���ļ���С _fseeki64(file, 0, SEEK_END);
	fseek(file, 0, SEEK_END);
	long fileSize = ftell(file);
	rewind(file);

	// �洢��buffer
	unsigned char* fileBuffer = (unsigned char*)malloc(fileSize);
	if (fileBuffer)
	{
		memset(fileBuffer, 0, fileSize);
		fread_s(fileBuffer, fileSize, fileSize, 1, file);
	}
	fclose(file);

	// ����ʽд�뵽һ��.h�ļ���
	const char* outputFileName = (argc == 2) ? "dll.h" : args[2];
	fopen_s(&file, outputFileName, "wb");
	if (fileBuffer && file != NULL)
	{
		fputs("#pragma once\n", file);
		fprintf_s(file, "#define XOR_ENCODE_KEY 0x%02X\n", XOR_ENCODE_KEY);
		fprintf_s(file, "unsigned char sysData[%d] = {\n", fileSize);
		fprintf_s(file, "\t");
		for (int i = 0; i < fileSize; i++)
		{
			fileBuffer[i] ^= XOR_ENCODE_KEY;
			fprintf_s(file, "0x%02X, ", fileBuffer[i]);
			if ((i + 1) % MAX_LINE_LENGTH == 0)
			{
				fprintf_s(file, "\n\t");
			}
		}
		fprintf_s(file, "\n};");
		fclose(file);
		free(fileBuffer);
	}
	
	return 0;
}