#include "Header.h"

HMODULE WINAPI _LoadLibraryA(LPCSTR lpLibFileName) {
  printf("LoadLibraryA called with parameter: %s\n", lpLibFileName);
  return LoadLibraryA(lpLibFileName);
}
BOOL WINAPI _CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {
  printf("CreateProcessA called with parameter: %s\n", lpApplicationName);
  return CreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes,
                        lpThreadAttributes, bInheritHandles, dwCreationFlags,
                        lpEnvironment, lpCurrentDirectory, lpStartupInfo,
                        lpProcessInformation);
}
BOOL WINAPI _WriteFile(HANDLE hFile, (nNumberOfBytesToWrite)LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
  printf("WriteFile called with parameter: %d\n", nNumberOfBytesToWrite);
  return WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite,
                   lpNumberOfBytesWritten, lpOverlapped);
}
BOOL WINAPI _ReadFile(HANDLE hFile, (nNumberOfBytesToRead, *lpNumberOfBytesRead)(FILE)LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) {
  printf("ReadFile called with parameter: %d\n", nNumberOfBytesToRead);
  return ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead,
                  lpOverlapped);
}
LSTATUS APIENTRY _RegSetValueExA(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, (cbData)CONST BYTE* lpData, DWORD cbData) {
  printf("RegSetValueExA called with parameter: %s\n", lpValueName);
  return RegSetValueExA(hKey, lpValueName, Reserved, dwType, lpData, cbData);
}