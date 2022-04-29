#pragma once
#include <Windows.h>
#include <vector>

struct ProcessInfo {
	int PID;
	int numberOfFunction;
	char** functionName;
};

ProcessInfo* parseJson(char* json, int fileSize);
int countProcessInfo(char* json);
char* getNextString(char* data, int pos);