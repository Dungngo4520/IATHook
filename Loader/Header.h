#include <stdio.h>
#include <vector>
#include <Windows.h>
#include <Psapi.h>
#include <winternl.h>

struct ProcessInfo {
	int PID;
	int numberOfFunction;
	char** function;
};

ProcessInfo *parseJson(char *json, int fileSize);
int countProcessInfo(char *json);
char *getNextString(char *data, int pos);
int countString(char *data, int start, int end);
void printInfo(ProcessInfo *p, int size);
void freeMemory(ProcessInfo *p, int size);
bool readJson(char *json, void **output, unsigned long *size);
void HookIAT(char* functionName, DWORD64 newFunction, LPVOID* oldFunction);