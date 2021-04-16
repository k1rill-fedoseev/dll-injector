#include <windows.h>
#include <winternl.h>
#include <tchar.h>
#include <psapi.h>

#include "Remote.h"

#define JUMP_IF_ERROR(err, func, label) \
			err = func; \
			if (err != 0) goto label;

DWORD CreateProc(LPCTSTR targetApp, HANDLE& hProc, HANDLE& hThread) {
	STARTUPINFO si = {};
	PROCESS_INFORMATION pi = {};

	if (
		!CreateProcess(
			targetApp,
			nullptr, nullptr, nullptr, true,
			CREATE_SUSPENDED, nullptr, nullptr,
			&si, &pi)
	) {
		DWORD err = GetLastError();
		_tprintf(_T("CreateProcess has failed with code 0x%x\n"), err);
		return err;
	}

	Sleep(1000);

	hProc = pi.hProcess;
	hThread = pi.hThread;

	return ERROR_SUCCESS;
}

DWORD LoopEntry(HANDLE& hProc, HANDLE& hThread, ULONG_PTR& pRemoteEntryPoint, WORD& originalEntryPoint) {
	PROCESS_BASIC_INFORMATION pbi = {};
	ULONG len;
	PEB peb = {};
	IMAGE_DOS_HEADER dos = {};
	IMAGE_NT_HEADERS32 nt = {};

	NTSTATUS status = NtQueryInformationProcess(hProc, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &len);
	if (status < 0) {
		_tprintf(_T("LoopEntry has failed with code -0x%x\n"), -status);
		return status;
	}

	
	DWORD err = ReadRemote<PEB>(hProc, (ULONG_PTR)pbi.PebBaseAddress, peb);
	if (err != 0) return err;

	ULONG_PTR pRemoteImageBase = (ULONG_PTR)peb.Reserved3[1];

	err = ReadRemote<IMAGE_DOS_HEADER>(hProc, pRemoteImageBase, dos);
	if (err != 0) return err;

	err = ReadRemote<IMAGE_NT_HEADERS32>(hProc, pRemoteImageBase + dos.e_lfanew, nt);
	if (err != 0) return err;

	pRemoteEntryPoint = pRemoteImageBase + nt.OptionalHeader.AddressOfEntryPoint;

	WORD patchedEntryPoint = 0xfeeb;
	err = ReadRemote<WORD>(hProc, pRemoteEntryPoint, originalEntryPoint);
	if (err != 0) return err;

	err = WriteRemote<WORD>(hProc, pRemoteEntryPoint, patchedEntryPoint);
	if (err != 0) return err;

	err = ResumeThread(hThread);
	if (err == 0) {
		err = GetLastError();
		_tprintf(_T("ResumeThread has failed with code 0x%x\n"), err);
		return err;
	}

	Sleep(1000);

	return ERROR_SUCCESS;
}

DWORD Inject(HANDLE hProc, HANDLE hThread, ULONG_PTR pRemoteLoadLibrary) {
	UCHAR shellx86[]{
		/*0x00: */ 0x90, 0x90, 0x90, 0x90, 0x90,       // nop
		/*0x05: */ 0x68, 0x00, 0x00, 0x00, 0x00,       // push string
		/*0x0A: */ 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, // call LoadLibraryW
		/*0x10: */ 0xF7, 0xD8,                         // neg eax
		/*0x12: */ 0x1B, 0xC0,                         // sbb eax, eax
		/*0x14: */ 0xF7, 0xD8,                         // neg eax
		/*0x16: */ 0x48,                               // dec eax
		/*0x17: */ 0xC3,                               // ret

		/*0x18: */ 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
		/*0x20: */ 0x00, 0x00, 0x00, 0x00,
		/*0x24: */ 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,

		// C:\Users\KIRUHA\source\repos\DLLInjector\Release\DLLInjection.dll
		// 433a5c55736572735c4b49525548415c736f757263655c7265706f735c444c4c496e6a6563746f725c52656c656173655c444c4c496e6a656374696f6e2e646c6c
		/*0x30: */ 0x43, 0x00, 0x3a, 0x00, 0x5c, 0x00, 0x55, 0x00, 0x73, 0x00, 0x65, 0x00, 0x72, 0x00, 0x73, 0x00, 0x5c, 0x00, 0x4b, 0x00, 0x49, 0x00, 0x52, 0x00, 0x55, 0x00, 0x48, 0x00, 0x41, 0x00, 0x5c, 0x00, 0x73, 0x00, 0x6f, 0x00, 0x75, 0x00, 0x72, 0x00, 0x63, 0x00, 0x65, 0x00, 0x5c, 0x00, 0x72, 0x00, 0x65, 0x00, 0x70, 0x00, 0x6f, 0x00, 0x73, 0x00, 0x5c, 0x00, 0x44, 0x00, 0x4c, 0x00, 0x4c, 0x00, 0x49, 0x00, 0x6e, 0x00, 0x6a, 0x00, 0x65, 0x00, 0x63, 0x00, 0x74, 0x00, 0x6f, 0x00, 0x72, 0x00, 0x5c, 0x00, 0x52, 0x00, 0x65, 0x00, 0x6c, 0x00, 0x65, 0x00, 0x61, 0x00, 0x73, 0x00, 0x65, 0x00, 0x5c, 0x00, 0x44, 0x00, 0x4c, 0x00, 0x4c, 0x00, 0x49, 0x00, 0x6e, 0x00, 0x6a, 0x00, 0x65, 0x00, 0x63, 0x00, 0x74, 0x00, 0x69, 0x00, 0x6f, 0x00, 0x6e, 0x00, 0x2e, 0x00, 0x64, 0x00, 0x6c, 0x00, 0x6c, 0x00
	};

	LPVOID pShellRemote = VirtualAllocEx(hProc, nullptr, sizeof(shellx86), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	ULONG_PTR shellBase = (ULONG_PTR)pShellRemote;
	ULONG_PTR funcOffset = shellBase + 0x20;
	ULONG_PTR strOffset = shellBase + 0x30;

	memcpy(shellx86 + 0x20, &pRemoteLoadLibrary, sizeof(ULONG_PTR));
	memcpy(shellx86 + 0x06, &strOffset, sizeof(ULONG_PTR));
	memcpy(shellx86 + 0x0c, &funcOffset, sizeof(ULONG_PTR));

	SIZE_T written = 0;
	// move memory
	WriteProcessMemory(hProc, pShellRemote, shellx86, sizeof(shellx86), &written);

	// create remote thread
	DWORD tid;
	HANDLE hRemoteThread = CreateRemoteThread(hProc, nullptr, 0, LPTHREAD_START_ROUTINE(shellBase), nullptr, 0, &tid);

	WaitForSingleObject(hRemoteThread, INFINITE);

	DWORD exitCode = 0xf;
	GetExitCodeThread(hRemoteThread, &exitCode);

	Sleep(1000);

	CloseHandle(hRemoteThread);

	return 0;
}

extern "C" NTSYSCALLAPI NTSTATUS NTAPI NtSuspendProcess(HANDLE proc);
extern "C" NTSYSCALLAPI NTSTATUS NTAPI NtResumeProcess(HANDLE proc);

DWORD DeloopEntry(HANDLE& hProc, HANDLE& hThread, ULONG_PTR& pRemoteEntryPoint, WORD& originalEntryPoint) {
	NTSTATUS status = NtSuspendProcess(hProc);
	if (status < 0) {
		_tprintf(_T("NtSuspendProcess has failed with code -0x%x\n"), -status);
		return status;
	}

	DWORD err = WriteRemote<WORD>(hProc, pRemoteEntryPoint, originalEntryPoint);
	if (err != 0) return err;

	status = NtResumeProcess(hProc);
	if (status < 0) {
		_tprintf(_T("NtResumeProcess has failed with code -0x%x\n"), -status);
		return status;
	}

	Sleep(1000);

	return 0;
}

DWORD FindLoadLibrary(HANDLE& hProc, HANDLE& hThread, ULONG_PTR& pRemoteLoadLibrary) {
	LPCSTR targetLib = "KERNEL32.dll";
	LPCSTR targetFunc = "LoadLibraryW";
	DWORD needed = 0;
	HMODULE* hModules = nullptr;

	EnumProcessModules(hProc, nullptr, 0, &needed);

	DWORD size = needed;
	DWORD amount = size / sizeof(HMODULE);
	hModules = (HMODULE*)malloc(size);
	EnumProcessModules(hProc, hModules, size, &needed);

	for (DWORD i = 0; i < amount; i++) {
		ULONG_PTR moduleBase = (ULONG_PTR)hModules[i];
		IMAGE_DOS_HEADER dos = {};
		IMAGE_NT_HEADERS32 nt = {};
		
		ReadRemote<IMAGE_DOS_HEADER>(hProc, moduleBase, dos);
		ReadRemote<IMAGE_NT_HEADERS32>(hProc, moduleBase + dos.e_lfanew, nt);
		
		IMAGE_DATA_DIRECTORY exportDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

		if (exportDir.Size == 0) continue;

		IMAGE_EXPORT_DIRECTORY moduleExport = {};
		ReadRemote<IMAGE_EXPORT_DIRECTORY>(hProc, moduleBase + exportDir.VirtualAddress, moduleExport);

		CHAR moduleName[MAX_PATH];
		DWORD moduleNameLen = 0;

		ReadRemote<CHAR>(hProc, moduleBase + moduleExport.Name, moduleName, moduleNameLen);

		if (strcmp(moduleName, targetLib)) continue;

		DWORD numOfFuncs = moduleExport.NumberOfFunctions;

		ULONG_PTR* functionNamesRva = (ULONG_PTR*)malloc(sizeof(ULONG_PTR) * numOfFuncs);
		ULONG_PTR* functionAddrsRva = (ULONG_PTR*)malloc(sizeof(ULONG_PTR) * numOfFuncs);
		WORD* functionOrdinals = (WORD*)malloc(sizeof(WORD) * numOfFuncs);

		ReadRemote<ULONG_PTR>(hProc, moduleBase + moduleExport.AddressOfNames, functionNamesRva, numOfFuncs);
		ReadRemote<ULONG_PTR>(hProc, moduleBase + moduleExport.AddressOfFunctions, functionAddrsRva, numOfFuncs);
		ReadRemote<WORD>(hProc, moduleBase + moduleExport.AddressOfNameOrdinals, functionOrdinals, numOfFuncs);

		for (DWORD j = 0; j < numOfFuncs; j++) {
			CHAR functionName[MAX_PATH];
			DWORD functionNameLen = 0;

			ReadRemote<CHAR>(hProc, moduleBase + functionNamesRva[j], functionName, functionNameLen);

			if (!strcmp(functionName, targetFunc)) {
				// use ordinals
				WORD ordinal = functionOrdinals[j];
				pRemoteLoadLibrary = moduleBase + functionAddrsRva[ordinal];
				break;
			}
		}

		free(functionNamesRva);
		free(functionAddrsRva);
		break;
	}

	free(hModules);

	return 0;
}

int main() {
	LPCTSTR targetApp = _T("C:\\Windows\\SysWOW64\\notepad.exe");
	HANDLE hProc = INVALID_HANDLE_VALUE;
	HANDLE hThread = INVALID_HANDLE_VALUE;
	DWORD status = ERROR_SUCCESS;
	ULONG_PTR pRemoteEntryPoint = 0;
	WORD originalEntryPoint = 0;
	ULONG_PTR pRemoteLoadLibrary = 0;

	// create suspended process
	JUMP_IF_ERROR(status, CreateProc(targetApp, hProc, hThread), HANDLE_ERROR);
	
	// loop entrypoint
	JUMP_IF_ERROR(status, LoopEntry(hProc, hThread, pRemoteEntryPoint, originalEntryPoint), HANDLE_ERROR);

	// find loadlibrary
	JUMP_IF_ERROR(status, FindLoadLibrary(hProc, hThread, pRemoteLoadLibrary), HANDLE_ERROR);

	// inject shellcode
	JUMP_IF_ERROR(status, Inject(hProc, hThread, pRemoteLoadLibrary), HANDLE_ERROR);

	// return entry
	JUMP_IF_ERROR(status, DeloopEntry(hProc, hThread, pRemoteEntryPoint, originalEntryPoint), HANDLE_ERROR);

	return 0;
HANDLE_ERROR:
	_tprintf(_T("ERROR: 0x%x\n"), status);
	return status;
}