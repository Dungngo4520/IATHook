#include "Header.h"
#include <conio.h>

int main(int argc, char* argv[]) {
	char* data = NULL;
	unsigned long size = 0;
	int numberOfProcess = 0;
	ProcessInfo* p = NULL;
	char* dllPath = "..\\IATHook\\IATHook.dll";
	char* fileName = (char*)"input.json";
	LPVOID function = NULL, parameter = NULL;
	bool hooked = false;

	if (!readJson(fileName, (void**)&data, &size)) {
		printf("Error: Cannot read file %s\n", fileName);
		return -1;
	}

	numberOfProcess = countProcessInfo(data);
	p = parseJson(data, numberOfProcess);
	while (1) {
		if (!hooked) {
			printf("press space to hook.\n");
			if (_getch() == 32) {
				for (int i = 0; i < numberOfProcess; i++) {
					HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, p[i].PID);
					if (hProcess) {
						if (!loadDll(dllPath, hProcess)) {
							printf("Failed to load DLL\n");
						}

						for (int j = 0; j < p[i].numberOfFunction; j++) {
							if (!CreateHook(p[i].function[j], dllPath, hProcess)) {
								printf("Failed to create hook\n");
							}
							else hooked = true;
						}
						CloseHandle(hProcess);
					}
				}
			}
		}
		if (hooked) {
			printf("hooked! press space to unhook.\n");
			if (_getch() == 32) {
				for (int i = 0; i < numberOfProcess; i++) {
					HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, p[i].PID);
					if (hProcess) {
						if (!UnHook(dllPath, hProcess)) {
							printf("Failed to UnHook\n");
						}
						else hooked = false;
						printf("Unhooked for process %d\n", p[i].PID);
						CloseHandle(hProcess);
					}
				}
			}
		}
	}

	freeMemory(p, numberOfProcess);
	return 0;
}

bool loadDll(char* dllPath, HANDLE hProcess) {
	LPVOID function = NULL, parameter = NULL;
	HANDLE thread = NULL;

	//get LoadLibrary address
	HMODULE hMod = GetModuleHandle("kernel32.dll");
	if (hMod) function = (LPVOID)GetProcAddress(hMod, "LoadLibraryA");
	if (!function) {
		hMod = LoadLibrary("kernel32.dll");
		if (hMod) function = (LPVOID)GetProcAddress(hMod, "LoadLibraryA");
	}
	if (!function) {
		printf("Failed to find function address. Error: %d\n", GetLastError());
		return false;
	}

	// allocate dll name in target process
	parameter = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!parameter) {
		printf("Failed to allocate memory in target process. Error: %d\n", GetLastError());
		return false;
	}

	// load dll
	if (!WriteProcessMemory(hProcess, parameter, dllPath, strlen(dllPath) + 1, NULL)) {
		printf("Failed to write in target memory. Error: %d\n", GetLastError());
		return false;
	}

	thread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)function, parameter, NULL, NULL);
	if (!thread) {
		printf("Failed to create remote thread. Error: %d\n", GetLastError());
		return false;
	}

	WaitForSingleObject(thread, INFINITE);

	if (!VirtualFreeEx(hProcess, parameter, 0, MEM_RELEASE)) {
		printf("Failed to free memory. Error: %d\n", GetLastError());
	}
	return true;
}
bool CreateHook(char* functionName, char* dllPath, HANDLE hProcess) {
	LPVOID function = NULL, parameter = NULL;
	HANDLE thread = NULL;

	// get CreateHook function address
	function = GetRemoteFunctionAddress(hProcess, "IATHook.dll", "CreateHook");
	if (!function) {
		printf("Failed to find function address. Error: %d\n", GetLastError());
		return false;
	}

	//allocate function name
	parameter = VirtualAllocEx(hProcess, NULL, strlen(functionName) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!parameter) {
		printf("Failed to allocate memory in target process. Error: %d\n", GetLastError());
		return false;
	}
	// hook by running CreateHook
	if (!WriteProcessMemory(hProcess, parameter, functionName, strlen(functionName) + 1, NULL)) {
		printf("Failed to write in target memory. Error: %d\n", GetLastError());
		return false;
	}

	thread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)function, parameter, NULL, NULL);
	if (!thread) {
		printf("Failed to create remote thread. Error: %d\n", GetLastError());
		return false;
	}
	WaitForSingleObject(thread, INFINITE);

	if (!VirtualFreeEx(hProcess, parameter, 0, MEM_RELEASE)) {
		printf("Failed to free memory. Error: %d\n", GetLastError());
	}
	return true;
}
bool UnHook(char* dllPath, HANDLE hProcess) {
	LPVOID function = NULL;
	HANDLE thread = NULL;

	// get UnHook function address
	function = GetRemoteFunctionAddress(hProcess, "IATHook.dll", "UnHook");
	if (!function) {
		printf("Failed to find function address. Error: %d\n", GetLastError());
		return false;
	}

	// hook by running CreateHook
	thread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)function, NULL, NULL, NULL);
	if (!thread) {
		printf("Failed to create remote thread. Error: %d\n", GetLastError());
		return false;
	}
	WaitForSingleObject(thread, INFINITE);
	return true;
}

FARPROC GetRemoteFunctionAddress(HANDLE hProcess, char* dllName, char* functionName) {
	DWORD64 RemoteModuleBaseVA = 0;
	IMAGE_DOS_HEADER DosHeader = { 0 };
	DWORD Signature = 0;
	IMAGE_FILE_HEADER FileHeader = { 0 };
	IMAGE_OPTIONAL_HEADER64 OptHeader64 = { 0 };
	IMAGE_OPTIONAL_HEADER32 OptHeader32 = { 0 };
	IMAGE_DATA_DIRECTORY ExportDirectory = { 0 };
	IMAGE_EXPORT_DIRECTORY ExportTable = { 0 };
	DWORD64 ExportFunctionTableVA = 0;
	DWORD64 ExportNameTableVA = 0;
	DWORD64 ExportOrdinalTableVA = 0;
	DWORD* ExportFunctionTable = NULL;
	DWORD* ExportNameTable = NULL;
	WORD* ExportOrdinalTable = NULL;
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32;

	// get remote module base address
	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(hProcess));
	if (hModuleSnap == INVALID_HANDLE_VALUE) {
		printf("CreateToolhelp32Snapshot failed\n");
		return NULL;
	}

	me32.dwSize = sizeof(MODULEENTRY32);

	if (!Module32First(hModuleSnap, &me32)) {
		printf("Module32First failed\n");
		CloseHandle(hModuleSnap);
		return(FALSE);
	}
	do {
		if (strncmp(me32.szModule, dllName, strlen(me32.szModule)) == 0) {
			RemoteModuleBaseVA = (DWORD64)me32.modBaseAddr;
			break;
		}
	} while (Module32Next(hModuleSnap, &me32));

	if (RemoteModuleBaseVA != 0) {
		ReadProcessMemory(hProcess, (LPCVOID)RemoteModuleBaseVA, &DosHeader, sizeof(DosHeader), NULL);
		ReadProcessMemory(hProcess, (LPCVOID)(RemoteModuleBaseVA + DosHeader.e_lfanew + sizeof(Signature)), &FileHeader, sizeof(FileHeader), NULL);

		if (FileHeader.SizeOfOptionalHeader == sizeof(OptHeader64)) {
			ReadProcessMemory(hProcess, (LPCVOID)(RemoteModuleBaseVA + DosHeader.e_lfanew + sizeof(Signature) + sizeof(FileHeader)), &OptHeader64, FileHeader.SizeOfOptionalHeader, NULL);
			ExportDirectory.VirtualAddress = (OptHeader64.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]).VirtualAddress;
			ExportDirectory.Size = (OptHeader64.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]).Size;
		}
		else if (FileHeader.SizeOfOptionalHeader == sizeof(OptHeader32)) {
			ReadProcessMemory(hProcess, (LPCVOID)(RemoteModuleBaseVA + DosHeader.e_lfanew + sizeof(Signature) + sizeof(FileHeader)), &OptHeader32, FileHeader.SizeOfOptionalHeader, NULL);
			ExportDirectory.VirtualAddress = (OptHeader32.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]).VirtualAddress;
			ExportDirectory.Size = (OptHeader32.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]).Size;
		}

		ReadProcessMemory(hProcess, (LPCVOID)(RemoteModuleBaseVA + ExportDirectory.VirtualAddress), &ExportTable, sizeof(ExportTable), NULL);
		ExportFunctionTableVA = RemoteModuleBaseVA + ExportTable.AddressOfFunctions;
		ExportNameTableVA = RemoteModuleBaseVA + ExportTable.AddressOfNames;
		ExportOrdinalTableVA = RemoteModuleBaseVA + ExportTable.AddressOfNameOrdinals;

		ExportFunctionTable = (DWORD*)calloc(ExportTable.NumberOfFunctions, sizeof(DWORD));
		ExportNameTable = (DWORD*)calloc(ExportTable.NumberOfNames, sizeof(DWORD));
		ExportOrdinalTable = (WORD*)calloc(ExportTable.NumberOfNames, sizeof(WORD));

		if (ExportFunctionTable == NULL || ExportNameTable == NULL || ExportOrdinalTable == NULL) {
			return NULL;
		}

		ReadProcessMemory(hProcess, (LPCVOID)ExportFunctionTableVA, ExportFunctionTable, ExportTable.NumberOfFunctions * sizeof(DWORD), NULL);
		ReadProcessMemory(hProcess, (LPCVOID)ExportNameTableVA, ExportNameTable, ExportTable.NumberOfNames * sizeof(DWORD), NULL);
		ReadProcessMemory(hProcess, (LPCVOID)ExportOrdinalTableVA, ExportOrdinalTable, ExportTable.NumberOfNames * sizeof(WORD), NULL);

		for (int i = 0; i < ExportTable.NumberOfNames; i++) {
			char* TempFunctionName = (char*)calloc(1024, sizeof(char));
			char TempChar;
			bool Done = false;// Reset for next name

			/* Get the function name one character at a time because we don't know how long it is */
			for (int j = 0; !Done; j++) {
				/* Get next character */
				ReadProcessMemory(hProcess, (LPCVOID)(RemoteModuleBaseVA + ExportNameTable[i] + j), &TempChar, sizeof(TempChar), NULL);

				//TempFunctionName.push_back(TempChar); // Add it to the string
				snprintf(TempFunctionName, 1024, "%s%c", TempFunctionName, TempChar);
				/* If it's NUL we are done */
				if (TempChar == (CHAR)'\0') {
					Done = true;
				}
			}

			if (TempFunctionName && strncmp(TempFunctionName, functionName, strlen(TempFunctionName)) == 0) {
				FARPROC TempReturn = (FARPROC)(RemoteModuleBaseVA + ExportFunctionTable[ExportOrdinalTable[i]]);
				free(ExportFunctionTable);
				free(ExportNameTable);
				free(ExportOrdinalTable);
				return TempReturn;
			}

		}
	}
}