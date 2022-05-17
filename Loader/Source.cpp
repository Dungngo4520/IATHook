#include "Header.h"
#include <conio.h>

int main(int argc, char* argv[]) {
	char *data = NULL;
	unsigned long size = 0;
	int numberOfProcess = 0;
	ProcessInfo *p = NULL;
	char* dllPath = "..\\IATHook\\IATHook.dll";
	char *fileName = (char *)"input.json";
	LPVOID function = NULL, parameter = NULL;
	bool hooked = false;

	if (!readJson(fileName, (void **)&data, &size)) {
		printf("Error: Cannot read file %s\n", fileName);
		return -1;
	}

	numberOfProcess = countProcessInfo(data);
	p = parseJson(data, numberOfProcess);

	for (int i = 0; i < numberOfProcess; i++) {
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, p[i].PID);
		if (hProcess) {
			//get LoadLibrary address
			LPVOID function = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

			// allocate dll name in target process
			LPVOID parameter = (LPVOID)VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

			// load dll
			int t = WriteProcessMemory(hProcess, parameter, dllPath, strlen(dllPath) + 1, NULL);
			HANDLE h = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)function, parameter, NULL, NULL);
			WaitForSingleObject(h, INFINITE);

			VirtualFreeEx(hProcess, parameter, strlen(dllPath) + 1, MEM_RELEASE | MEM_DECOMMIT);

			for (int j = 0; j < p[i].numberOfFunction; j++) {
				// get CreateHook function address
				function = GetProcAddress(GetModuleHandle(dllPath), "CreateHook");
				if (!function)function = GetProcAddress(LoadLibrary(dllPath), "CreateHook");

				//allocate function name
				parameter = VirtualAllocEx(hProcess, NULL, strlen(p[i].function[j]) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

				// hook by running CreateHook
				WriteProcessMemory(hProcess, parameter, p[i].function[j], strlen(p[i].function[j]) + 1, NULL);
				CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)function, parameter, NULL, NULL);

				VirtualFreeEx(hProcess, parameter, strlen(p[i].function[j]) + 1, MEM_RELEASE | MEM_DECOMMIT);
				hooked = true;
			}
			CloseHandle(hProcess);
		}
	}
	if (hooked) {
		printf("hooked! press esc to unhook.\n");
		if (_getch() == 127) {
			for (int i = 0; i < numberOfProcess; i++) {
				HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, p[i].PID);
				if (hProcess) {
					//get LoadLibrary address
					LPVOID function = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "FreeLibrary");

					// allocate dll name in target process
					LPVOID parameter = (LPVOID)VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

					// load dll
					int t = WriteProcessMemory(hProcess, parameter, dllPath, strlen(dllPath) + 1, NULL);
					HANDLE h = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)function, parameter, NULL, NULL);
					WaitForSingleObject(h, INFINITE);

					VirtualFreeEx(hProcess, parameter, strlen(dllPath) + 1, MEM_RELEASE | MEM_DECOMMIT);
					CloseHandle(hProcess);
				}
				printf("Unhook for process %d\n", p[i].PID);
			}
		}
	}

	freeMemory(p, numberOfProcess);
	return 0;
}

ProcessInfo *parseJson(char *data, int fileSize) {
	char *ptr = data;
	ProcessInfo *p = NULL;
	int numerOfProcess = 0;

	numerOfProcess = countProcessInfo(data);
	p = (ProcessInfo *)calloc(numerOfProcess, sizeof(ProcessInfo));

	if (p)
		for (int i = 0; i < numerOfProcess; i++) {
			// get PID
			ptr = strstr(ptr, "\"pid\"");
			if (!ptr) {
				break;
			}
			ptr = strchr(ptr, ':');
			if (!ptr) {
				break;
			}
			p[i].PID = atoi(++ptr);

			// get functions
			ptr = strstr(ptr, "\"functions\"");
			if (!ptr) {
				break;
			}

			ptr = strchr(ptr, ':');
			if (!ptr) {
				break;
			}

			char *end = strchr(ptr, ']');
			p[i].numberOfFunction = countString(data, ptr - data, end - data);
			p[i].function = (char **)calloc(p[i].numberOfFunction, sizeof(char *));
			if (!p[i].function) {
				break;
			}

			for (int j = 0; j < p[i].numberOfFunction; j++) {
				p[i].function[j] = getNextString(data, ptr - data);
				ptr = strchr(ptr, ',') + 1;
				if (!ptr) {
					break;
				}
			}
		}
	return p;
}

// count number of process from json list (count "pid")
int countProcessInfo(char *data) {
	int count = 0;
	char *ptr = data;

	do {
		ptr = strstr(ptr, "\"pid\"");
		if (ptr) {
			count++;
			ptr++;
		}
	} while (ptr);
	return count;
}

// count number of string from start to end, string is surrounded with
// ""
int countString(char *data, int start, int end) {
	int count = 0;

	while (start < end) {
		if (*(data + start) == '\"') {
			count++;
		}
		start++;
	}
	return count / 2;
}

// get next string in ""
char *getNextString(char *data, int start) {
	char *begin = NULL, *end = NULL, *res = NULL;

	begin = strchr(data + start, '"') + 1;
	if (!begin) {
		return NULL;
	}
	end = strchr(begin, '"');
	if (!end) {
		return NULL;
	}

	res = (char *)calloc(end - begin + 1, 1);
	if (res != 0) {
		strncpy_s(res, end - begin + 1, begin, end - begin);
	}
	return res;
}

void printInfo(ProcessInfo *p, int size) {
	for (int i = 0; i < size; i++) {
		printf("PID: %d\n", p[i].PID);
		for (int j = 0; j < p[i].numberOfFunction; j++) {
			printf("%s\n", p[i].function[j]);
		}
	}
}

void freeMemory(ProcessInfo *p, int size) {
	for (int i = 0; i < size; i++) {
		for (int j = 0; j < p[i].numberOfFunction; j++) {
			free(p[i].function[j]);
		}
		free(p[i].function);
	}
	free(p);
}

bool readJson(char *fileName, void **output, unsigned long *size) {
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD fileSize = 0, byteRead = 0;
	char *data = NULL;

	hFile = CreateFile(fileName, GENERIC_ALL, FILE_SHARE_READ, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("Cannot open file\n");
		return FALSE;
	}
	fileSize = GetFileSize(hFile, NULL);
	data = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize);
	if (!ReadFile(hFile, data, fileSize, &byteRead, NULL)) {
		printf("Cannot open file\n");
		return FALSE;
	}
	*output = data;
	*size = fileSize;
	CloseHandle(hFile);
	return TRUE;
}
