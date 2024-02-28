#include <iostream>
using namespace std;

#define XOR_ENCODE_KEY 0xAB
#define MAX_LINE_LENGTH 40

// 该功能是将PE文件转换成一个.h头文件,其中用一个字符数组存储PE的二进制码
int main(int argc, char* args[], char** env)
{
	if (argc < 2)
	{
		cout << "参数不对,举例: build.exe dll路径" << endl;
		return 1;
	}

	FILE* file = NULL;
	fopen_s(&file, args[1], "rb");
	if (!file)
	{
		cout << "文件不存在" << endl;
		return 1;
	}

	// 求文件大小 _fseeki64(file, 0, SEEK_END);
	fseek(file, 0, SEEK_END);
	long fileSize = ftell(file);
	rewind(file);

	// 存储到buffer
	unsigned char* fileBuffer = (unsigned char*)malloc(fileSize);
	if (fileBuffer)
	{
		memset(fileBuffer, 0, fileSize);
		fread_s(fileBuffer, fileSize, fileSize, 1, file);
	}
	fclose(file);

	// 按格式写入到一个.h文件中
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