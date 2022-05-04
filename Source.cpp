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
                HookIAT(p[i].PID, "LoadLibraryA", _LoadLibraryA);
            } else if (strncmp(p[i].function[j], "CreateProcessA", 14) == 0) {
                HookIAT(p[i].PID, "CreateProcessA", _CreateProcessA);
            } else if (strncmp(p[i].function[j], "WriteFile", 9) == 0) {
                HookIAT(p[i].PID, "WriteFile", _WriteFile);
            } else if (strncmp(p[i].function[j], "ReadFile", 8) == 0) {
                HookIAT(p[i].PID, "ReadFile", _ReadFile);
            } else if (strncmp(p[i].function[j], "RegSetValueExA", 13) == 0) {
                HookIAT(p[i].PID, "RegSetValueExA", _RegSetValueExA);
            }
        }
    }

    freeMemory(p, numberOfProcess);
    return 0;
}

void HookIAT(int pid, char *functionName, void *newFunction) {
    char *base = NULL;
    PROCESS_BASIC_INFORMATION *pBasicInfo = NULL;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        printf("Error: Cannot open process %d\n", pid);
        return;
    }

    pBasicInfo = (PROCESS_BASIC_INFORMATION *)malloc(sizeof(PROCESS_BASIC_INFORMATION));
    NtQueryInformationProcess(hProcess, 0, pBasicInfo, sizeof(PROCESS_BASIC_INFORMATION), NULL);
    if (ReadProcessMemory(hProcess, pBasicInfo->PebBaseAddress, &base, sizeof(base), NULL) == 0) {
        printf("Error: Cannot read process memory\n");
        return;
    }

    IMAGE_DOS_HEADER *pDosHeader = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *pNtHeader = (IMAGE_NT_HEADERS *)((DWORD64)base + pDosHeader->e_lfanew);
    IMAGE_IMPORT_DESCRIPTOR *pImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR *)((DWORD64)base + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    if (pNtHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        IMAGE_IMPORT_DESCRIPTOR *pImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR *)((DWORD64)base + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        IMAGE_THUNK_DATA32 *pThunkData = (IMAGE_THUNK_DATA32 *)((DWORD64)base + pImportDescriptor->FirstThunk);
        while (pImportDescriptor->Name != 0) {
            IMAGE_IMPORT_BY_NAME *pImportByName = (IMAGE_IMPORT_BY_NAME *)((DWORD64)base + pImportDescriptor->Name);
            if (strncmp((char *)pImportByName->Name, functionName, strlen(functionName)) == 0) {
                printf("Found %s\n", functionName);
                pThunkData->u1.Function = (DWORD64)newFunction;
            }
            pImportDescriptor++;
            pThunkData++;
        }
    } else if (pNtHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_IMPORT_DESCRIPTOR *pImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR *)((DWORD64)base + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        IMAGE_THUNK_DATA64 *pThunkData = (IMAGE_THUNK_DATA64 *)((DWORD64)base + pImportDescriptor->FirstThunk);
        while (pImportDescriptor->Name != 0) {
            IMAGE_IMPORT_BY_NAME *pImportByName = (IMAGE_IMPORT_BY_NAME *)((DWORD64)base + pImportDescriptor->Name);
            if (strncmp((char *)pImportByName->Name, functionName, strlen(functionName)) == 0) {
                printf("Found %s\n", functionName);
                pThunkData->u1.Function = (DWORD64)newFunction;
            }
            pImportDescriptor++;
            pThunkData++;
        }
    }
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

unsigned long long RVA2Offset(unsigned long long base, unsigned long long rva) {
    IMAGE_DOS_HEADER *dosHeader = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS64 *ntHeader = (IMAGE_NT_HEADERS64 *)(base + dosHeader->e_lfanew);
    IMAGE_SECTION_HEADER *sectionHeader = (IMAGE_SECTION_HEADER *)(base + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
    for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
        if (rva >= sectionHeader[i].VirtualAddress && rva < sectionHeader[i].VirtualAddress + sectionHeader[i].SizeOfRawData) {
            return rva - sectionHeader[i].VirtualAddress + sectionHeader[i].PointerToRawData;
        }
    }
    return 0;
}