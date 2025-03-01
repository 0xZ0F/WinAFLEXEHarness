#include <Windows.h>
#include <iostream>
#include <fstream>
#include <chrono>

/// <summary>
/// Convert RVA to Offset.
/// </summary>
/// <param name="rva"></param>
/// <param name="psh"></param>
/// <param name="pnt"></param>
/// <returns>Returns the offset.</returns>
DWORD Rva2Offset(DWORD rva, PIMAGE_SECTION_HEADER psh, PIMAGE_NT_HEADERS pnt)
{
	// https://stackoverflow.com/questions/15960437/how-to-read-import-directory-table-in-c
	size_t i = 0;
	PIMAGE_SECTION_HEADER pSeh;
	if(rva == 0)
	{
		return (rva);
	}
	pSeh = psh;
	for(i = 0; i < pnt->FileHeader.NumberOfSections; i++)
	{
		if(rva >= pSeh->VirtualAddress && rva < pSeh->VirtualAddress + pSeh->Misc.VirtualSize)
		{
			break;
		}
		pSeh++;
	}
	return (rva - pSeh->VirtualAddress + pSeh->PointerToRawData);
}

/// <summary>
/// Load a PE from disk into allocated mem.
/// </summary>
/// <param name="lpTarget">Target PE (DLL or EXE)</param>
/// <returns>Returns a pointer to the read DLL on success, nullptr on failure.</returns>
BYTE* Read_PE(LPCSTR lpTarget)
{
	BYTE* pSrcData = nullptr;

	// Check if DLL file exists ?
	if(!GetFileAttributesA(lpTarget))
	{
		std::cerr << "File doesn't exist\n";
		return nullptr;
	}

	// Open file and go to end.
	std::ifstream file(lpTarget, std::ios::binary | std::ios::ate);

	// Did it work
	if(file.fail())
	{
		std::cerr << "Failed to open file " << lpTarget << " : " << file.rdstate() << "\n";
		file.close();
		return nullptr;
	}

	// Get file size.
	auto fileSize = file.tellg();

	// "Since in modern portable executables the first 4096 (0x1000) bytes are reserved for the PE header it's just a simple check that noone tries to pass an invalid file to the injector."
	// "There's a field in the PEHeaders called SizeOfHeaders that tells you the exact size of the headers in that DLL (which is always 0x1000 or 4096 bytes in modern libraries.) Broihon was just lazy and decided to hardcode it."
	if(fileSize < 0x1000)
	{
		std::cerr << "Filesize is invalid.\n";
		file.close();
		return nullptr;
	}

	// Allocate buffer for file data.
	pSrcData = new BYTE[fileSize];

	// check allocationg.
	if(!pSrcData)
	{
		std::cerr << "Memory allocating failed\n";
		file.close();
		return nullptr;
	}

	// Move to beginning of file and read data into memory.
	file.seekg(0, std::ios::beg);
	file.read(reinterpret_cast<char*>(pSrcData), fileSize);
	file.close();

	return pSrcData;
}

bool PrintHeaderInfo(LPCSTR lpTarget)
{
	if(lpTarget == nullptr)
	{
		std::cerr << "PrintHeaderInfo() nullptr\n";
		return false;
	}

	BYTE* fileData = Read_PE(lpTarget);
	if(fileData == nullptr)
	{
		std::cerr << "Failed to read file\n";
		return false;
	}

	// DOS header starts at base
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileData;

	printf("--- DOS HEADER ---\n");
	printf("e_magic: %X\n", dosHeader->e_magic);
	printf("e_lfanew: %X\n", dosHeader->e_lfanew);

	// NT header starts at +e_lfanew
	PIMAGE_NT_HEADERS ntHeader = PIMAGE_NT_HEADERS(fileData + dosHeader->e_lfanew);

	printf("\n--- NT HEADER ---\n");
	printf("Signature: %X\n", ntHeader->Signature);

	// From the NT header get the file and optional headers
	IMAGE_OPTIONAL_HEADER optionalHeader = ntHeader->OptionalHeader;
	IMAGE_FILE_HEADER fileHeader = ntHeader->FileHeader;

	printf("\n--- FILE HEADER ---\n");
	printf("Machine: %X\n", fileHeader.Machine);
	printf("TimeDateStamp: %u\n", fileHeader.TimeDateStamp);

	printf("\n--- OPTIONAL HEADER ---\n");
	printf("Magic: %X\n", optionalHeader.Magic);
	printf("ImageBase: %llX\n", optionalHeader.ImageBase);

	// Import data dir
	IMAGE_DATA_DIRECTORY importDir = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	printf("\n--- IMPORT DIRECTORY ---\n");
	printf("VirtualAddress: %X\n", importDir.VirtualAddress);
	printf("Size: %X\n", importDir.Size);

	// Export dir
	IMAGE_DATA_DIRECTORY exportDir = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	printf("\n--- EXPORT DIRECTORY ---\n");
	printf("VirtualAddress: %X\n", exportDir.VirtualAddress);
	printf("Size: %X\n", exportDir.Size);

	// Section Header(s)
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeader);
	DWORD sectionSize = (DWORD)sizeof(IMAGE_SECTION_HEADER);

	PIMAGE_SECTION_HEADER importSection = { 0 };
	PIMAGE_SECTION_HEADER exportSection = { 0 };

	printf("\n--- SECTIONS ---\n");
	for(int x = 0; x < fileHeader.NumberOfSections; x++)
	{
		// 8 is the max len of sectionHeader->Name
		printf("%.8s @ %X\n", section->Name, section->VirtualAddress);

		// Save the section which contains the imports
		// Compares the address of the import dir to the address range of the curr section
		if(importDir.VirtualAddress >= section->VirtualAddress
			&& importDir.VirtualAddress < section->VirtualAddress + section->Misc.VirtualSize)
		{
			importSection = section;
		}

		if(exportDir.VirtualAddress >= section->VirtualAddress
			&& exportDir.VirtualAddress < section->VirtualAddress + section->Misc.VirtualSize)
		{
			exportSection = section;
		}

		section++;
	}

	printf("\n--- IMPORTS ---\n");
	if(importSection)
	{
		// Parse Imports
		printf("Import section: %.8s\n", importSection->Name);

		/*
			Get pointer to import descriptor's file offset. Note that the formula for calculating file offset is:
			imageBaseAddress + pointerToRawDataOfTheSectionContainingRVAofInterest + (RVAofInterest - SectionContainingRVAofInterest.VirtualAddress)
		*/
		uintptr_t importDataOffset = (uintptr_t)fileData + importSection->PointerToRawData;
		PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importDataOffset + (importDir.VirtualAddress - importSection->VirtualAddress));

		// Loop over every module
		for(; importDescriptor->Name != 0; importDescriptor++)
		{
			printf("\n%s\n", (char*)(importDataOffset + (importDescriptor->Name - importSection->VirtualAddress)));

			uintptr_t thunk = importDescriptor->OriginalFirstThunk == 0 ? importDescriptor->FirstThunk : importDescriptor->OriginalFirstThunk;
			PIMAGE_THUNK_DATA thunkData = (PIMAGE_THUNK_DATA)(importDataOffset + (thunk - importSection->VirtualAddress));

			for(; thunkData->u1.AddressOfData != 0; thunkData++)
			{
				// Hacky check for ordinals
				if(thunkData->u1.AddressOfData > 0x80000000)
				{
					printf("\tOrdinal: %x\n", (WORD)thunkData->u1.AddressOfData);
				}
				else
				{
					printf("\t%s\n", (char*)(importDataOffset + (thunkData->u1.AddressOfData - importSection->VirtualAddress + 2)));
				}
			}

		}
	}
	else
	{
		printf("No imports found.\n");
	}

	printf("\n--- EXPORTS ---\n");
	if(exportSection)
	{
		// Parse Exports
		printf("Export section: %.8s\n", exportSection->Name);

		uintptr_t exportDataOffset = (uintptr_t)fileData + exportSection->PointerToRawData;
		PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(exportDataOffset + (exportDir.VirtualAddress - exportSection->VirtualAddress));

		// First name is DLL, this is followed by NULL terminated exported funcs
		LPCSTR dllName = (LPCSTR)fileData + Rva2Offset(exports->Name, exportSection, ntHeader);
		// Function names aren't required, only an ord is fine. The ord and name "arrays" should be parallel.
		USHORT* ord = (USHORT*)(fileData + Rva2Offset(exports->AddressOfNameOrdinals, exportSection, ntHeader));

		// AddressOfNames is an array of offsets for the exported names
		UINT* exportNameOffset = (UINT*)(fileData + Rva2Offset(exports->AddressOfNames, exportSection, ntHeader));
		LPCSTR exportName = (LPCSTR)fileData + Rva2Offset(*exportNameOffset, exportSection, ntHeader);

		printf("Exported DLL Name: %s\n", dllName);
		printf("Number of exported names: %d\n", exports->NumberOfNames);
		printf("Number of exported functions: %d\n", exports->NumberOfFunctions);

		// For each function print name/ord
		printf("ORD | NAME\n");
		for(size_t x = 0; x < exports->NumberOfFunctions; x++, ord++, exportNameOffset++)
		{
			exportName = (LPCSTR)fileData + Rva2Offset(*exportNameOffset, exportSection, ntHeader);
			printf(" %hu | ", (*ord) + exports->Base);
			if(*exportName)
			{
				printf("%s", exportName);
			}
			else
			{
				printf("NONAME");
			}
			printf("\n");
		}
	}
	else
	{
		printf("No exports found.\n");
	}

	delete[] fileData;
	return true;
}

int main(int argc, char* argv[])
{
	//if (argc < 2) {
	//	fprintf(stderr, "Usage: %s EXE_PATH", argv[0]);
	//	return 0;
	//}

	char szTarget[] = R"(C:\Windows\System32\dpapi.dll)";
	if(!PrintHeaderInfo(szTarget))
	{
		return -1;
	}

	return 0;
}