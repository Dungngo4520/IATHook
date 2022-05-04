#include <stdio.h>
#include <Windows.h>
#include <vector>
#include <Psapi.h>
#include <winternl.h>

struct ProcessInfo {
    int PID;
    int numberOfFunction;
    char **function;
};

ProcessInfo *parseJson(char *json, int fileSize);
int countProcessInfo(char *json);
char *getNextString(char *data, int pos);
int countString(char *data, int start, int end);
void printInfo(ProcessInfo *p, int size);
void freeMemory(ProcessInfo *p, int size);
bool readJson(char *json, void **output, unsigned long *size);
void HookIAT(int pid, char *functionName, void *newFunction);
unsigned long long RVA2Offset(unsigned long long base, unsigned long long rva);

HMODULE WINAPI _LoadLibraryA(LPCSTR lpLibFileName);
BOOL WINAPI _CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
                            LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags,
                            LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo,
                            LPPROCESS_INFORMATION lpProcessInformation);
BOOL WINAPI _WriteFile(HANDLE hFile, (nNumberOfBytesToWrite)LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
                       LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
BOOL WINAPI _ReadFile(HANDLE hFile, (nNumberOfBytesToRead, *lpNumberOfBytesRead)(FILE)LPVOID lpBuffer,
                      DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
LSTATUS APIENTRY _RegSetValueExA(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType,
                                 (cbData)CONST BYTE *lpData, DWORD cbData);