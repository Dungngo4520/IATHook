#include "Header.h"

int main(int argc, char *argv[]) {
	char *data = NULL;
	unsigned long size = 0;
	int numberOfProcess = 0;
	ProcessInfo *p = NULL;
	DWORD64 oldLoadLibrary=0, oldCreateProcess=0, oldWriteFile=0, oldReadFile=0, oldRegSetValue=0;
	
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
				HookIAT(p[i].PID, "LoadLibraryA", (DWORD64)&_LoadLibraryA, &oldLoadLibrary);
			}
			else if (strncmp(p[i].function[j], "CreateProcessA", 14) == 0) {
				HookIAT(p[i].PID, "CreateProcessA", (DWORD64)&_CreateProcessA, &oldCreateProcess);
			}
			else if (strncmp(p[i].function[j], "WriteFile", 9) == 0) {
				HookIAT(p[i].PID, "WriteFile", (DWORD64)&_WriteFile, &oldWriteFile);
			}
			else if (strncmp(p[i].function[j], "ReadFile", 8) == 0) {
				HookIAT(p[i].PID, "ReadFile", (DWORD64)&_ReadFile, &oldReadFile);
			}
			else if (strncmp(p[i].function[j], "RegSetValueExA", 13) == 0) {
				HookIAT(p[i].PID, "RegSetValueExA", (DWORD64)&_RegSetValueExA, &oldRegSetValue);
			}
		}
	}

	freeMemory(p, numberOfProcess);
	return 0;
}

void HookIAT(int PID, char * functionName, DWORD64 newFunction, DWORD64 * oldFunction) {
	PROCESS_BASIC_INFORMATION *pBasicInfo = NULL;
	HANDLE hProcess = INVALID_HANDLE_VALUE;
	char* processPath = NULL;
	HMODULE hMod = NULL;
	MODULEINFO moduleInfo;
	IMAGE_DOS_HEADER *pDosHeader = NULL;
	IMAGE_NT_HEADERS *pNtHeader = NULL;
	IMAGE_IMPORT_DESCRIPTOR *pImportDescriptor = NULL;

	//get Process handle
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (hProcess == NULL) {
		printf("Error: Cannot open process %d. Error: %d\n", PID, GetLastError());
		return;
	}

	//get base address of process
	processPath = (char*)malloc(MAX_PATH);
	GetModuleFileNameEx(hProcess, NULL, processPath, MAX_PATH);
	LoadLibrary(processPath);
	hMod = GetModuleHandle(processPath);
	if (!hMod) {
		printf("Error: %d\n", GetLastError());
	}
	GetModuleInformation(hProcess, hMod, &moduleInfo, sizeof(MODULEINFO));

	//get import descriptor;
	char* base = (char*)moduleInfo.lpBaseOfDll;
	pDosHeader = (IMAGE_DOS_HEADER *)base;
	pNtHeader = (IMAGE_NT_HEADERS *)((DWORD64)base + pDosHeader->e_lfanew);
	pImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR *)((DWORD64)base + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	//x86
	if (pNtHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		//iterate dll
		while (pImportDescriptor->Name != 0) {
			IMAGE_THUNK_DATA32 *pFirstThunk = (IMAGE_THUNK_DATA32 *)((DWORD64)base + pImportDescriptor->FirstThunk);
			IMAGE_THUNK_DATA32 *pOriginalFirstThunk = (IMAGE_THUNK_DATA32 *)((DWORD64)base + pImportDescriptor->OriginalFirstThunk);

			//iterate function name
			while (pOriginalFirstThunk->u1.AddressOfData != 0) {
				IMAGE_IMPORT_BY_NAME *pImportByName = (IMAGE_IMPORT_BY_NAME *)((DWORD64)base + pOriginalFirstThunk->u1.AddressOfData);

				if (strncmp((char *)pImportByName->Name, functionName, strlen(functionName)) == 0) {
					printf("Found %s in %s\n", (char*)pImportByName->Name, (char*)(pImportDescriptor->Name + base));
					DWORD accessProtect;

					//change protection
					if (!VirtualProtectEx(hProcess, &pFirstThunk->u1.Function, sizeof(DWORD*), PAGE_EXECUTE_READWRITE, &accessProtect)) {
						printf("Cant change protection. Error: %d\n", GetLastError());
						return;
					}

					*oldFunction = pFirstThunk->u1.Function;
					pFirstThunk->u1.Function = newFunction;
					if (!WriteProcessMemory(hProcess, &pFirstThunk->u1.Function, &newFunction, sizeof(newFunction), NULL)) {
						printf("Cant write to function. Error: %d\n", GetLastError());
					}
					
					//unchange protection
					if (!VirtualProtectEx(hProcess, &pFirstThunk->u1.Function, sizeof(DWORD*), accessProtect, &accessProtect)) {
						printf("Cant change protection. Error: %d\n", GetLastError());
						return;
					}
				}
				pOriginalFirstThunk++;
				pFirstThunk++;
			}
			pImportDescriptor++;
		}
	}
	//x64
	else if (pNtHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		//iterate dll
		while (pImportDescriptor->Name != 0) {
			IMAGE_THUNK_DATA64 *pFirstThunk = (IMAGE_THUNK_DATA64 *)((DWORD64)base + pImportDescriptor->FirstThunk);
			IMAGE_THUNK_DATA64 *pOriginalFirstThunk = (IMAGE_THUNK_DATA64 *)((DWORD64)base + pImportDescriptor->OriginalFirstThunk);

			//iterate function name
			while (pOriginalFirstThunk->u1.AddressOfData != 0) {
				IMAGE_IMPORT_BY_NAME *pImportByName = (IMAGE_IMPORT_BY_NAME *)((DWORD64)base + pOriginalFirstThunk->u1.AddressOfData);

				if (strncmp((char *)pImportByName->Name, functionName, strlen(functionName)) == 0) {
					printf("Found %s in %s\n", (char*)pImportByName->Name, (char*)(pImportDescriptor->Name + base));
					DWORD accessProtect;

					//change protection
					if (!VirtualProtectEx(hProcess, &pFirstThunk->u1.Function, sizeof(DWORD64*), PAGE_EXECUTE_READWRITE, &accessProtect)) {
						printf("Cant change protection. Error: %d\n", GetLastError());
						return;
					}

					*oldFunction = pFirstThunk->u1.Function;
					//pFirstThunk->u1.Function = newFunction;
					if (!WriteProcessMemory(hProcess, &pFirstThunk->u1.Function, &newFunction, sizeof(newFunction), NULL)) {
						printf("Cant write to function. Error: %d\n", GetLastError());
					}

					//unchange protection
					if (!VirtualProtectEx(hProcess, &pFirstThunk->u1.Function, sizeof(DWORD64*), accessProtect, &accessProtect)) {
						printf("Cant change protection. Error: %d\n", GetLastError());
						return;
					}
				}
				pOriginalFirstThunk++;
				pFirstThunk++;
			}
			pImportDescriptor++;
		}
	}
	return;
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
