#include "Header.h"

void main() {
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD fileSize = 0, byteRead = 0;
	char* data = NULL;

	hFile = CreateFile("input.json", GENERIC_ALL, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("Cannot open file");
		return;
	}
	fileSize = GetFileSize(hFile, NULL);
	data = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize);
	if (!ReadFile(hFile, data, fileSize, &byteRead, NULL)) {
		printf("Cannot open file");
		return;
	}

	printf("%s", getNextString(data, 0));
	getchar();
}

ProcessInfo* parseJson(char* json, int fileSize) {
	char* ptr = json;
	ProcessInfo* p = NULL;
	int numerOfProcess = 0;


	numerOfProcess = countProcessInfo(json);
	p = (ProcessInfo*)calloc(numerOfProcess, sizeof(ProcessInfo));

	for (int i = 0; i < fileSize; i++) {
		ptr = strstr(ptr, "\"pid\"");
		if (ptr == NULL) {
			break;
		}
	}
	while (ptr) {
		//parse PID
		ptr = strstr(ptr, "\"pid\"");
		if (ptr == NULL) {
			break;
		}
		ptr = strchr(ptr, ':');
		if (ptr == NULL) {
			break;
		}
		ptr++;
		p->PID = strtol(ptr, &ptr, 10);

		//parse functions
		ptr = strstr(ptr, "\"functions\"");
		if (ptr == NULL) {
			break;
		}
		ptr = strchr(ptr, '[');
		if (ptr == NULL) {
			break;
		}



	}
	return p;
}

int countProcessInfo(char* json) {
	int count = 0;
	char* ptr = json;
	while (ptr) {
		ptr = strstr(ptr, "\"pid\"");
		if (ptr != NULL) {
			count++;
			ptr++;
		}
	}
	return count;
}

char* getNextString(char* data, int pos) {
	int start = strchr(data + pos, '"') - data;
	int end = strchr(data + start + 1, '"') - data;
	char* res = (char*)malloc(end - start);
	strncpy_s(res, end - start, data + start, end - start);
	return res;
}