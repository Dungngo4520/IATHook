#include "Header.h"

ProcessInfo* parseJson(char* data, int fileSize) {
	char* ptr = data;
	ProcessInfo* p = NULL;
	int numerOfProcess = 0;

	numerOfProcess = countProcessInfo(data);
	p = (ProcessInfo*)calloc(numerOfProcess, sizeof(ProcessInfo));

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

			char* end = strchr(ptr, ']');
			p[i].numberOfFunction = countString(data, ptr - data, end - data);
			p[i].function = (char**)calloc(p[i].numberOfFunction, sizeof(char*));
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
int countProcessInfo(char* data) {
	int count = 0;
	char* ptr = data;

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
int countString(char* data, int start, int end) {
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
char* getNextString(char* data, int start) {
	char* begin = NULL, * end = NULL, * res = NULL;

	begin = strchr(data + start, '"') + 1;
	if (!begin) {
		return NULL;
	}
	end = strchr(begin, '"');
	if (!end) {
		return NULL;
	}

	res = (char*)calloc(end - begin + 1, 1);
	if (res != 0) {
		strncpy_s(res, end - begin + 1, begin, end - begin);
	}
	return res;
}

void printInfo(ProcessInfo* p, int size) {
	for (int i = 0; i < size; i++) {
		printf("PID: %d\n", p[i].PID);
		for (int j = 0; j < p[i].numberOfFunction; j++) {
			printf("%s\n", p[i].function[j]);
		}
	}
}

void freeMemory(ProcessInfo* p, int size) {
	for (int i = 0; i < size; i++) {
		for (int j = 0; j < p[i].numberOfFunction; j++) {
			free(p[i].function[j]);
		}
		if (p[i].function) free(p[i].function);
	}
	free(p);
}

bool readJson(char* fileName, void** output, unsigned long* size) {
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD fileSize = 0, byteRead = 0;
	char* data = NULL;

	hFile = CreateFile(fileName, GENERIC_ALL, FILE_SHARE_READ, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("Cannot open file\n");
		return FALSE;
	}
	fileSize = GetFileSize(hFile, NULL);
	data = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize);
	if (!ReadFile(hFile, data, fileSize, &byteRead, NULL)) {
		printf("Cannot open file\n");
		return FALSE;
	}
	*output = data;
	*size = fileSize;
	CloseHandle(hFile);
	return TRUE;
}
