#pragma once

#include <windows.h>

template<class T>
DWORD ReadRemote(
	_In_ HANDLE hProc,
	_In_ ULONG_PTR offset,
	_Out_ T& value
) {
	SIZE_T numBytesRead = 0;
	if (ReadProcessMemory(hProc, (LPCVOID)offset, &value, sizeof(T), &numBytesRead) == FALSE) {
		DWORD err = GetLastError();
		_tprintf(_T("ReadRemote has failed with code 0x%x\n"), err);
		return err;
	}
	return 0;
}

template<class T>
DWORD ReadRemote(
	_In_ HANDLE hProc,
	_In_ ULONG_PTR offset,
	_Out_ T* value,
	_Inout_ DWORD& amount
) {
	ULONG_PTR p = offset;
	DWORD counter = 0;
	T zero = {};

	for (;;) {
		T current;
		DWORD err = ReadRemote<T>(hProc, p, current);
		if (err != 0) return err;
		value[counter] = current;
		counter++;

		if (amount != 0 && amount == counter) break;

		p += sizeof(T);

		if (amount == 0 && memcmp(&current, &zero, sizeof(T)) == 0) break;
	}

	if (amount == 0) amount = --counter;

	return 0;
}


template<class T>
DWORD WriteRemote(
	_In_ HANDLE hProc,
	_In_ ULONG_PTR offset,
	_In_ const T& value
) {
	SIZE_T numBytesWritten = 0;
	if (WriteProcessMemory(hProc, (LPVOID)offset, &value, sizeof(T), &numBytesWritten) == FALSE) {
		DWORD err = GetLastError();
		_tprintf(_T("WriteRemote has failed with code 0x%x\n"), err);
		return err;
	}
	return 0;
}