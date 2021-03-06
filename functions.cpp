#include "Header.h"

HMODULE WINAPI _LoadLibraryA(LPCSTR lpLibFileName) {
	time_t t;
	FILE* f;
	char* datetime = NULL;

	t = time(NULL);
	datetime = (char*)calloc(26, sizeof(char));
	if (datetime) {
		ctime_s(datetime, 26, &t);
		datetime[strlen(datetime) - 1] = '\0';
	}

	const char fileName[] = "C:\\Users\\Public\\log.txt";
	fopen_s(&f, fileName, "a+");
	if (f) {
		fprintf_s(f, "%s, PID: %d, Name: %s, Parameter: (%s)\n", datetime, GetCurrentProcessId(), "LoadLibraryA", lpLibFileName);
		fclose(f);
		printf("LoadLibraryA hooked. Log at %s\n", fileName);
	}


	FuncLoadLibrary loadLibrary = (FuncLoadLibrary)oldLoadLibrary;
	return loadLibrary(lpLibFileName);
}
BOOL WINAPI _CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {
	time_t t;
	FILE* f;
	char* datetime = NULL;

	t = time(NULL);
	datetime = (char*)calloc(26, sizeof(char));
	if (datetime) {
		ctime_s(datetime, 26, &t);
		datetime[strlen(datetime) - 1] = '\0';
	}

	const char fileName[] = "C:\\Users\\Public\\log.txt";
	fopen_s(&f, fileName, "a+");
	if (f) {
		fprintf_s(f, "%s, PID: %d, Name: %s, Parameter: (%s, %s, %p, %p, %d, %d, %p, %s, %p, %p)\n", datetime, GetCurrentProcessId(), "CreateProcessA", lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
		fclose(f);
		printf("CreateProcessA hooked. Log at %s\n", fileName);
	}


	FuncCreateProcessA createProcess = (FuncCreateProcessA)oldCreateProcess;
	return createProcess(lpApplicationName, lpCommandLine, lpProcessAttributes,
		lpThreadAttributes, bInheritHandles, dwCreationFlags,
		lpEnvironment, lpCurrentDirectory, lpStartupInfo,
		lpProcessInformation);
}
BOOL WINAPI _WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
	time_t t;
	FILE* f;
	char* datetime = NULL;

	t = time(NULL);
	datetime = (char*)calloc(26, sizeof(char));
	if (datetime) {
		ctime_s(datetime, 26, &t);
		datetime[strlen(datetime) - 1] = '\0';
	}

	const char fileName[] = "C:\\Users\\Public\\log.txt";
	fopen_s(&f, fileName, "a+");
	if (f) {
		fprintf_s(f, "%s, PID: %d, Name: %s, Parameter: (%p, %p, %d, %p, %p)\n", datetime, GetCurrentProcessId(), "WriteFile", hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
		fclose(f);
		printf("WriteFile hooked. Log at %s\n", fileName);
	}


	FuncWriteFile writeFile = (FuncWriteFile)oldWriteFile;
	return writeFile(hFile, lpBuffer, nNumberOfBytesToWrite,
		lpNumberOfBytesWritten, lpOverlapped);
}
BOOL WINAPI _ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) {
	time_t t;
	FILE* f;
	char* datetime = NULL;

	t = time(NULL);
	datetime = (char*)calloc(26, sizeof(char));
	if (datetime) {
		ctime_s(datetime, 26, &t);
		datetime[strlen(datetime) - 1] = '\0';
	}

	const char fileName[] = "C:\\Users\\Public\\log.txt";
	fopen_s(&f, fileName, "a+");
	if (f) {
		fprintf_s(f, "%s, PID: %d, Name: %s, Parameter: (%p, %p, %d, %p, %p)\n", datetime, GetCurrentProcessId(), "ReadFile", hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
		fclose(f);
		printf("ReadFile hooked. Log at %s\n", fileName);
	}


	FuncReadFile readFile = (FuncReadFile)oldReadFile;
	return readFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}

LSTATUS APIENTRY _RegSetValueExA(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, CONST BYTE* lpData, DWORD cbData) {
	time_t t;
	FILE* f;
	char* datetime = NULL;

	t = time(NULL);
	datetime = (char*)calloc(26, sizeof(char));
	if (datetime) {
		ctime_s(datetime, 26, &t);
		datetime[strlen(datetime) - 1] = '\0';
	}

	const char fileName[] = "C:\\Users\\Public\\log.txt";
	fopen_s(&f, fileName, "a+");
	if (f) {
		fprintf_s(f, "%s, PID: %d, Name: %s, Parameter: (%p, %s, %d, %d, %p, %d)\n", datetime, GetCurrentProcessId(), "RegSetValueExA", hKey, lpValueName, Reserved, dwType, lpData, cbData);
		fclose(f);
		printf("RegSetValue hooked. Log at %s\n", fileName);
	}


	FuncRegSetValueExA regSetValue = (FuncRegSetValueExA)oldRegSetValue;
	return regSetValue(hKey, lpValueName, Reserved, dwType, lpData, cbData);
}