#include "Header.h"

LPVOID oldLoadLibrary = 0, oldCreateProcess = 0, oldWriteFile = 0, oldReadFile = 0, oldRegSetValue = 0;
HMODULE hModule;


BOOL APIENTRY DllMain(HMODULE hDllModule, DWORD  callReason, LPVOID lpReserved) {
	switch (callReason) {
		case DLL_PROCESS_ATTACH:
			DisableThreadLibraryCalls(hDllModule);
			hModule = GetModuleHandle(0);
			break;
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
	}

	return TRUE;


	return 0;
}

void WINAPI UnHook() {
	LPVOID temp;
	if (oldLoadLibrary != 0) {
		HookIAT("LoadLibraryA", oldLoadLibrary, &temp);
		oldLoadLibrary = 0;
	}
	if (oldCreateProcess != 0) {
		HookIAT("CreateProcessA", oldCreateProcess, &temp);
		oldCreateProcess = 0;
	}
	if (oldWriteFile != 0) {
		HookIAT("WriteFile", oldWriteFile, &temp);
		oldWriteFile = 0;
	}
	if (oldReadFile != 0) {
		HookIAT("ReadFile", oldReadFile, &temp);
		oldReadFile = 0;
	}
	if (oldRegSetValue != 0) {
		HookIAT("RegSetValueExA", oldRegSetValue, &temp);
		oldRegSetValue = 0;
	}
}

void WINAPI CreateHook(char* functionName) {
	if (strcmp(functionName, "LoadLibraryA") == 0) {
		HookIAT(functionName, &_LoadLibraryA, &oldLoadLibrary);
	}
	else if (strcmp(functionName, "CreateProcessA") == 0) {
		HookIAT(functionName, &_CreateProcessA, &oldCreateProcess);
	}
	else if (strcmp(functionName, "WriteFile") == 0) {
		HookIAT(functionName, &_WriteFile, &oldWriteFile);
	}
	else if (strcmp(functionName, "ReadFile") == 0) {
		HookIAT(functionName, &_ReadFile, &oldReadFile);
	}
	else if (strcmp(functionName, "RegSetValueExA") == 0) {
		HookIAT(functionName, &_RegSetValueExA, &oldRegSetValue);
	}

}

bool HookIAT(char* functionName, LPVOID newFunction, LPVOID* oldFunction) {
	IMAGE_NT_HEADERS* pNtHeader = NULL;
	IMAGE_IMPORT_DESCRIPTOR* pImportDescriptor = NULL;

	char* base = (char*)hModule;
	pNtHeader = (IMAGE_NT_HEADERS*)((DWORD64)base + ((IMAGE_DOS_HEADER*)base)->e_lfanew);
	pImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)((DWORD64)base + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	//x86
	if (pNtHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		//iterate dll
		while (pImportDescriptor->Name != 0) {
			IMAGE_THUNK_DATA32* pFirstThunk = (IMAGE_THUNK_DATA32*)((DWORD64)base + pImportDescriptor->FirstThunk);
			IMAGE_THUNK_DATA32* pOriginalFirstThunk = (IMAGE_THUNK_DATA32*)((DWORD64)base + pImportDescriptor->OriginalFirstThunk);

			//iterate function name
			while (pOriginalFirstThunk->u1.AddressOfData != 0) {
				IMAGE_IMPORT_BY_NAME* pImportByName = (IMAGE_IMPORT_BY_NAME*)((DWORD64)base + pOriginalFirstThunk->u1.AddressOfData);

				if (strncmp((char*)pImportByName->Name, functionName, strlen(pImportByName->Name)) == 0) {
					DWORD accessProtect;

					//change protection
					if (!VirtualProtect(&pFirstThunk->u1.Function, sizeof(DWORD*), PAGE_EXECUTE_READWRITE, &accessProtect)) {
						printf("Cant change protection. Error: %d\n", GetLastError());
						return false;
					}

					*oldFunction = (LPVOID)pFirstThunk->u1.Function;
					pFirstThunk->u1.Function = (DWORD)newFunction;

					//unchange protection
					if (!VirtualProtect(&pFirstThunk->u1.Function, sizeof(DWORD*), accessProtect, &accessProtect)) {
						printf("Cant change protection. Error: %d\n", GetLastError());
						return false;
					}
					break;
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
			IMAGE_THUNK_DATA64* pFirstThunk = (IMAGE_THUNK_DATA64*)((DWORD64)base + pImportDescriptor->FirstThunk);
			IMAGE_THUNK_DATA64* pOriginalFirstThunk = (IMAGE_THUNK_DATA64*)((DWORD64)base + pImportDescriptor->OriginalFirstThunk);

			//iterate function name
			while (pOriginalFirstThunk->u1.AddressOfData != 0) {
				IMAGE_IMPORT_BY_NAME* pImportByName = (IMAGE_IMPORT_BY_NAME*)((DWORD64)base + pOriginalFirstThunk->u1.AddressOfData);

				if (strncmp((char*)pImportByName->Name, functionName, strlen(pImportByName->Name)) == 0) {
					DWORD accessProtect;

					//change protection
					if (!VirtualProtect(&pFirstThunk->u1.Function, sizeof(DWORD64*), PAGE_EXECUTE_READWRITE, &accessProtect)) {
						printf("Cant change protection. Error: %d\n", GetLastError());
						return false;
					}

					*oldFunction = (LPVOID)pFirstThunk->u1.Function;
					pFirstThunk->u1.Function = (DWORD64)newFunction;

					//unchange protection
					if (!VirtualProtect(&pFirstThunk->u1.Function, sizeof(DWORD64*), accessProtect, &accessProtect)) {
						printf("Cant change protection. Error: %d\n", GetLastError());
						return false;
					}
					break;
				}
				pOriginalFirstThunk++;
				pFirstThunk++;
			}
			pImportDescriptor++;
		}
	}
	return true;
}

