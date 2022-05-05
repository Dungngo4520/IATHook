#include "Header.h"

int main(int argc, char *argv[]) {
	char *data = NULL;
	unsigned long size = 0;
	int numberOfProcess = 0;
	ProcessInfo *p = NULL;
	
	char *fileName = (char *)"input.json";
	if (!readJson(fileName, (void **)&data, &size)) {
		printf("Error: Cannot read file %s\n", fileName);
		return -1;
	}

	numberOfProcess = countProcessInfo(data);
	p = parseJson(data, numberOfProcess);

	for (int i = 0; i < numberOfProcess; i++) {
		for (int j = 0; j < p[i].numberOfFunction; j++) {
			if (strncmp(p[i].function[j], "LoadLibraryA", 12) == 0) {
				HookIAT(p[i].PID, "LoadLibraryA", (DWORD64)&_LoadLibraryA);
			}
			else if (strncmp(p[i].function[j], "CreateProcessA", 14) == 0) {
				HookIAT(p[i].PID, "CreateProcessA", (DWORD64)&_CreateProcessA);
			}
			else if (strncmp(p[i].function[j], "WriteFile", 9) == 0) {
				HookIAT(p[i].PID, "WriteFile", (DWORD64)&_WriteFile);
			}
			else if (strncmp(p[i].function[j], "ReadFile", 8) == 0) {
				HookIAT(p[i].PID, "ReadFile", (DWORD64)&_ReadFile);
			}
			else if (strncmp(p[i].function[j], "RegSetValueExA", 13) == 0) {
				HookIAT(p[i].PID, "RegSetValueExA", (DWORD64)&_RegSetValueExA);
			}
		}
	}

	freeMemory(p, numberOfProcess);
	return 0;
}

void HookIAT(int pid, char *functionName, DWORD64 newFunction) {
	DWORD64* pOldFunction = NULL;
	DWORD accessProtectionValue, accessProtect;


	pOldFunction = (DWORD64*)FindFunction(pid, functionName);
	if (!pOldFunction) {
		return;
	}

	if (!VirtualProtect(pOldFunction, sizeof(PSIZE_T), PAGE_EXECUTE_READWRITE, &accessProtectionValue)) {
		printf("Cant change protection. Error: %d", GetLastError());
		return;
	}
	*pOldFunction = newFunction;
	if (!VirtualProtect(pOldFunction, sizeof(PSIZE_T), accessProtectionValue, &accessProtect)) {
		printf("Cant change protection. Error: %d", GetLastError());
		return;
	}
}

void* FindFunction(int PID, char* functionName) {
	PROCESS_BASIC_INFORMATION *pBasicInfo = NULL;
	HANDLE hProcess = INVALID_HANDLE_VALUE;
	char* processPath = NULL;
	HMODULE hMod = NULL;
	MODULEINFO moduleInfo;
	IMAGE_DOS_HEADER *pDosHeader = NULL;
	IMAGE_NT_HEADERS *pNtHeader = NULL;
	IMAGE_IMPORT_DESCRIPTOR *pImportDescriptor = NULL;

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (hProcess == NULL) {
		printf("Error: Cannot open process %d. Error: %d\n", PID, GetLastError());
		return 0;
	}
	processPath = (char*)malloc(MAX_PATH);
	GetModuleFileNameEx(hProcess, NULL, processPath, MAX_PATH);
	LoadLibrary(processPath);
	hMod = GetModuleHandle(processPath);
	if (!hMod) {
		printf("Error: %d", GetLastError());
	}
	GetModuleInformation(hProcess, hMod, &moduleInfo, sizeof(MODULEINFO));

	char* base = (char*)moduleInfo.lpBaseOfDll;
	pDosHeader = (IMAGE_DOS_HEADER *)base;
	pNtHeader = (IMAGE_NT_HEADERS *)((DWORD64)base + pDosHeader->e_lfanew);
	pImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR *)((DWORD64)base + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	if (pNtHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		pImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR *)((DWORD64)base + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		while (pImportDescriptor->Name != 0) {
			IMAGE_THUNK_DATA32 *pFirstThunk = (IMAGE_THUNK_DATA32 *)((DWORD64)base + pImportDescriptor->FirstThunk);
			IMAGE_THUNK_DATA32 *pOriginalFirstThunk = (IMAGE_THUNK_DATA32 *)((DWORD64)base + pImportDescriptor->OriginalFirstThunk);

			while (pOriginalFirstThunk->u1.AddressOfData != 0) {
				IMAGE_IMPORT_BY_NAME *pImportByName = (IMAGE_IMPORT_BY_NAME *)((DWORD64)base + pOriginalFirstThunk->u1.AddressOfData);
				if (strncmp((char *)pImportByName->Name, functionName, strlen(functionName)) == 0) {
					printf("Found %s\n", functionName);
					return &pFirstThunk->u1.Function;
				}
				pOriginalFirstThunk++;
				pFirstThunk++;
			}
			pImportDescriptor++;
		}
	}
	else if (pNtHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		pImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR *)((DWORD64)base + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		while (pImportDescriptor->Name != 0) {
			IMAGE_THUNK_DATA64 *pFirstThunk = (IMAGE_THUNK_DATA64 *)((DWORD64)base + pImportDescriptor->FirstThunk);
			IMAGE_THUNK_DATA64 *pOriginalFirstThunk = (IMAGE_THUNK_DATA64 *)((DWORD64)base + pImportDescriptor->OriginalFirstThunk);

			while (pOriginalFirstThunk->u1.AddressOfData != 0) {
				IMAGE_IMPORT_BY_NAME *pImportByName = (IMAGE_IMPORT_BY_NAME *)((DWORD64)base + pOriginalFirstThunk->u1.AddressOfData);
				if (strncmp((char *)pImportByName->Name, functionName, strlen(functionName)) == 0) {
					printf("Found %s\n", functionName);
					return &pFirstThunk->u1.Function;
				}
				pOriginalFirstThunk++;
				pFirstThunk++;
			}
			pImportDescriptor++;
		}
	}
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
		printf("Cannot open file");
		return FALSE;
	}
	fileSize = GetFileSize(hFile, NULL);
	data = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize);
	if (!ReadFile(hFile, data, fileSize, &byteRead, NULL)) {
		printf("Cannot open file");
		return FALSE;
	}
	*output = data;
	*size = fileSize;
	CloseHandle(hFile);
	return TRUE;
}