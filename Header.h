#include <stdio.h>
#include <vector>
#include <Windows.h>
#include <Psapi.h>
#include <winternl.h>

extern LPVOID oldLoadLibrary, oldCreateProcess, oldWriteFile, oldReadFile, oldRegSetValue;
typedef HMODULE (WINAPI *FuncLoadLibrary)(LPCSTR);
typedef BOOL (WINAPI *FuncCreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef BOOL(WINAPI* FuncWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL (WINAPI* FuncReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef LSTATUS (APIENTRY* FuncRegSetValueExA)(HKEY, LPCSTR, DWORD, DWORD, CONST BYTE *, DWORD);

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
void HookIAT(int PID, char* functionName, DWORD64 newFunction, LPVOID* oldFunction);

HMODULE WINAPI _LoadLibraryA(LPCSTR);
BOOL WINAPI _CreateProcessA(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
BOOL WINAPI _WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
BOOL WINAPI _ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
LSTATUS APIENTRY _RegSetValueExA(HKEY, LPCSTR, DWORD, DWORD, CONST BYTE *, DWORD);