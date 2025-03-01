#include <stdio.h>
#include <iostream>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#define EXE_PATH R"(C:\Dev\Fuzzing\WinAFLEXE\x64\Debug\EXETarget.exe)"
//#define EXE_PATH R"(C:\Program Files\FileZilla FTP Client\filezilla.exe)"
//#define DLL_PATH R"(C:\Windows\System32\dpapi.dll)"

using PrintHeadInfo_t = bool(*)(LPCSTR);

HMODULE g_hExe = NULL;
PrintHeadInfo_t g_fpFunc = NULL;

extern "C" __declspec(dllexport) __declspec(noinline) bool FuzzThis(char* szFilePath)
{
	if(NULL == g_fpFunc)
	{
		return false;
	}
	bool fRet = g_fpFunc(szFilePath);
	return fRet;
}

bool FixImports(HMODULE hModule)
{
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
	PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule +
		ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	while(importDesc->Name)
	{
		const char* dllName = (const char*)((BYTE*)hModule + importDesc->Name);
		HMODULE hLib = GetModuleHandleA(dllName);
		if(!hLib)
		{
			printf("GetModuleHandleA() %s %lu\n", dllName, GetLastError());
			importDesc++;
			continue;
		}

		PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + importDesc->FirstThunk);
		PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + importDesc->OriginalFirstThunk);

		while(origThunk->u1.AddressOfData)
		{
			if(origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				// Import by ordinal
				FARPROC func = GetProcAddress(hLib, (LPCSTR)(origThunk->u1.Ordinal & 0xFFFF));
				if(!func)
				{
					printf("Failed to resolve function by ordinal\n");
					return false;
				}
				thunk->u1.Function = (DWORD_PTR)func;
			}
			else
			{
				// Import by name
				PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)hModule + origThunk->u1.AddressOfData);
				FARPROC func = GetProcAddress(hLib, importByName->Name);
				if(!func)
				{
					printf("GetProcAddress() %s %lu\n", importByName->Name, GetLastError());
					return false;
				}

				DWORD dwOldProtect = 0;
				if(!VirtualProtect((void*)(&thunk->u1.Function), sizeof(thunk->u1.Function), PAGE_READWRITE, &dwOldProtect))
				{
					fprintf(stderr, "VirtualProtect() %lu\n", GetLastError());
					return false;
				}

				thunk->u1.Function = (DWORD_PTR)func;

				if(!VirtualProtect((void*)(&thunk->u1.Function), sizeof(thunk->u1.Function), dwOldProtect, &dwOldProtect))
				{
					fprintf(stderr, "VirtualProtect() %lu\n", GetLastError());
					return false;
				}
			}
			thunk++;
			origThunk++;
		}
		importDesc++;
	}

	return true;
}

int main(int argc, char* argv[])
{
	if(argc < 2)
	{
		fprintf(stderr, "Usage: %s DLL_PATH", argv[0]);
		return 1;
	}

	/*
		// May need to manually import some DLLs.

		if(!SetDllDirectoryA("C:\\Program Files\\FileZilla FTP Client"))
		{
			printf("SetDllDirectoryA() %lu\n", GetLastError());
			return 3;
		}

		hTmp = LoadLibraryA("libfzclient-commonui-private-3-68-1.dll");
		hTmp = LoadLibraryA("libfzclient-private-3-68-1.dll");
		hTmp = LoadLibraryA("libfilezilla-46.dll");
		hTmp = LoadLibraryA("wxbase32u_gcc_custom.dll");
		hTmp = LoadLibraryA("wxmsw32u_aui_gcc_custom.dll");
		hTmp = LoadLibraryA("wxmsw32u_core_gcc_custom.dll");
		hTmp = LoadLibraryA("wxmsw32u_xrc_gcc_custom.dll");
		hTmp = LoadLibraryA("libsqlite3-0.dll");
		hTmp = LoadLibraryA("MPR.dll");
		hTmp = LoadLibraryA("NETAPI32.dll");
		hTmp = LoadLibraryA("ole32.dll");
		hTmp = LoadLibraryA("POWRPROF.dll");
		hTmp = LoadLibraryA("SHELL32.dll");
		hTmp = LoadLibraryA("SHLWAPI.dll");
		hTmp = LoadLibraryA("USER32.dll");
		hTmp = LoadLibraryA("libgcc_s_seh-1.dll");
		hTmp = LoadLibraryA("libstdc++-6.dll");

		if(!SetDllDirectoryA(NULL))
		{
			printf("SetDllDirectoryA() %lu\n", GetLastError());
			return 4;
		}
	*/

	// For the EXETarget
	// Handle left open intentionally.
	HMODULE hTmp = LoadLibraryA("MSVCP140D.dll");
	if(!hTmp)
	{
		printf("LoadLibraryA() %lu\n", GetLastError());
		return 2;
	}

	g_hExe = LoadLibraryA(EXE_PATH);
	if(!g_hExe)
	{
		return 3;
	}

	if(!FixImports(g_hExe))
	{
		fprintf(stderr, "FixImports()\n");
		return 4;
	}

	/*
		// May need to call entrypoint.

		IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)g_hExe;
		IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)g_hExe + dosHeader->e_lfanew);
		DWORD entryPoint = ntHeaders->OptionalHeader.AddressOfEntryPoint;
		((void(*)())((BYTE*)g_hExe + entryPoint))();
	*/

	/*
		// Some instrumentation tools, such as TinyInst,
		// don't supress output. This is a workaround.
		// Alternatively, use WinAFL's distributed mode
		// and monitor with 'winafl-whatsup.py'.

		FILE* fp = NULL;
		if(freopen_s(&fp, "NUL", "w", stdout))
		{
			fprintf(stderr, "freopen_s() %lu\n", GetLastError());
			return 5;
		}
	*/

	// Update offset if required.
	// If using the example, it is the RVA to PrintHeaderInfo(...) in EXETarget.
	g_fpFunc = (PrintHeadInfo_t)((uintptr_t)g_hExe + 0x166E0);
	FuzzThis(argv[1]);
}