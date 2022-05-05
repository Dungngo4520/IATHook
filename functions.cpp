#include "Header.h"

HMODULE WINAPI _LoadLibraryA(LPCSTR lpLibFileName) {
	char* message = NULL;
	DWORD dwWritten = 0;
	HANDLE file;

	MessageBox(NULL, "Hooked", NULL, MB_ICONEXCLAMATION | MB_YESNO);

	file = CreateFile("C:\\Users\\Administrator\\Documents\\Visual Studio 2015\\Projects\\IATHook\\log.txt", FILE_GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	SetFilePointer(file, 0, NULL, FILE_END);

	message = (char*)malloc(100);
	sprintf_s(message, 100, "LoadLibraryA called with parameter: %s\n", lpLibFileName);
	WriteFile(file, message, strlen(message), &dwWritten, NULL);
	return LoadLibraryA(lpLibFileName);
}
BOOL WINAPI _CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {
	char* message = NULL;
	DWORD dwWritten = 0;
	HANDLE file;

	MessageBox(NULL, "Hooked", NULL, MB_ICONEXCLAMATION | MB_YESNO);
	file = CreateFile("C:\\Users\\Administrator\\Documents\\Visual Studio 2015\\Projects\\IATHook\\log.txt", FILE_GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	SetFilePointer(file, 0, NULL, FILE_END);

	message = (char*)malloc(100);
	sprintf_s(message, 100, "CreateProcessA called with parameter: %s\n", lpApplicationName);
	WriteFile(file, message, strlen(message), &dwWritten, NULL);

	return CreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes,
		lpThreadAttributes, bInheritHandles, dwCreationFlags,
		lpEnvironment, lpCurrentDirectory, lpStartupInfo,
		lpProcessInformation);
}
BOOL WINAPI _WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
	char* message = NULL;
	DWORD dwWritten = 0;
	HANDLE file;

	MessageBox(NULL, "Hooked", NULL, MB_ICONEXCLAMATION | MB_YESNO);
	file = CreateFile("C:\\Users\\Administrator\\Documents\\Visual Studio 2015\\Projects\\IATHook\\log.txt", FILE_GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	SetFilePointer(file, 0, NULL, FILE_END);

	message = (char*)malloc(100);
	sprintf_s(message, 100, "WriteFile called with parameter: %d\n", nNumberOfBytesToWrite);
	WriteFile(file, message, strlen(message), &dwWritten, NULL);
	return WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite,
		lpNumberOfBytesWritten, lpOverlapped);
}
BOOL WINAPI _ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) {
	char* message = NULL;
	DWORD dwWritten = 0;
	HANDLE file;

	MessageBox(NULL, "Hooked", NULL, MB_ICONEXCLAMATION | MB_YESNO);
	file = CreateFile("C:\\Users\\Administrator\\Documents\\Visual Studio 2015\\Projects\\IATHook\\log.txt", FILE_GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	SetFilePointer(file, 0, NULL, FILE_END);

	message = (char*)malloc(100);
	sprintf_s(message, 100, "ReadFile called with parameter: %d\n", nNumberOfBytesToRead);
	WriteFile(file, message, strlen(message), &dwWritten, NULL);

	return ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead,
		lpOverlapped);
}
LSTATUS APIENTRY _RegSetValueExA(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, CONST BYTE* lpData, DWORD cbData) {
	char* message = NULL;
	DWORD dwWritten = 0;
	HANDLE file;

	MessageBox(NULL, "Hooked", NULL, MB_ICONEXCLAMATION | MB_YESNO);
	file = CreateFile("C:\\Users\\Administrator\\Documents\\Visual Studio 2015\\Projects\\IATHook\\log.txt", FILE_GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	SetFilePointer(file, 0, NULL, FILE_END);

	message = (char*)malloc(100);
	sprintf_s(message, 100, "RegSetValueExA called with parameter: %s\n", lpValueName);
	WriteFile(file, message, strlen(message), &dwWritten, NULL);

	return RegSetValueExA(hKey, lpValueName, Reserved, dwType, lpData, cbData);
}