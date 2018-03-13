#include "stdafx.h"
#include "pe-loader.hpp"
#include "pe-loader-exception.hpp"

namespace grr
{
	typedef LONG(NTAPI *nt_suspend_process)(IN HANDLE process_handle);
	typedef LONG(NTAPI *nt_resume_process)(IN HANDLE process_handle);
	nt_suspend_process pfnNtSuspendProcess;
	nt_resume_process pfnNtResumeProcess;

	pe_loader::pe_loader(const std::string& library_name)
	{
		char library_path[MAX_PATH];

		library_name_ = library_name;

		//Search directorys other than the working directory (i.e, system32); otherwise attempts to load librarys such as user32.dll will fail.
		if (!SearchPathA(nullptr, library_name.c_str(), nullptr, MAX_PATH, library_path, nullptr))
			throw grr::pe_loader_exception("Unable to locate library.");

		//Map the file in to memory for quick IO and easy read access.
		const auto file = CreateFileA(library_path, GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

		if (file == INVALID_HANDLE_VALUE)
			throw grr::pe_loader_exception("Unable to open file.");

		//Attempt to create file mapping object.
		const auto file_map = CreateFileMapping(file, nullptr, PAGE_READONLY, 0, 0, nullptr);

		if (!file_map)
			throw grr::pe_loader_exception("Error create file mapping.");

		//Attempt to map file in to local address space.
		const auto file_view = MapViewOfFile(file_map, FILE_MAP_READ, 0, 0, 0);

		if (!file_view)
			throw grr::pe_loader_exception("Error mapping view of file in to local address space.");

		init(file_view, file, file_map);
	}


	pe_loader::pe_loader(const void* source_image)
	{
		init(source_image);
	}

	pe_loader::~pe_loader()
	{
		//Unmap file view
		if (file_map_)
		{
			UnmapViewOfFile(file_view_);
			CloseHandle(file_map_);
			CloseHandle(file_);
		}
	}

	void pe_loader::init(const void* view, const HANDLE file, const HANDLE file_map)
	{
		pfnNtSuspendProcess = reinterpret_cast<nt_suspend_process>(GetProcAddress(GetModuleHandleA("ntdll"), "NtSuspendProcess"));
		pfnNtResumeProcess = reinterpret_cast<nt_suspend_process>(GetProcAddress(GetModuleHandleA("ntdll"), "NtResumeProcess"));

		file_view_ = const_cast<void*>(view);
		file_ = file;
		file_map_ = file_map;

		//Initilize file DOS and NT headers.
		m_pFileDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(file_view_);

		//Validate DOS headers
		if (!is_valid_dos_header(m_pFileDosHeader))
			throw grr::pe_loader_exception("Invalid DOS header.");

		m_pFileNtHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(m_pFileDosHeader->e_lfanew + reinterpret_cast<LONG>(file_view_));

		//Validate NT Headers
		if (!is_valid_nt_headers(m_pFileNtHeaders))
			throw grr::pe_loader_exception("Invalid NT Headers.");
	}

	bool pe_loader::is_valid_nt_headers(const IMAGE_NT_HEADERS* nt_headers)
	{
		return (nt_headers->Signature == 'EP');
	}

	bool pe_loader::is_valid_dos_header(const IMAGE_DOS_HEADER* dos_header)
	{
		return (dos_header->e_magic == 'ZM');
	}

	void pe_loader::calculate_relocation(const HANDLE process, const long difference, const unsigned long base, const WORD offset)
	{
		const unsigned long relocation_type = offset >> 12;
		const unsigned long destination = offset & 0xFFF;

		switch (relocation_type)
		{
			//Only required relocations on an x86 system.
		case IMAGE_REL_BASED_HIGHLOW:
		{
			DWORD buffer = 0;

			if (!ReadProcessMemory(process, reinterpret_cast<unsigned long*>(destination + base), &buffer, sizeof(buffer), nullptr))
				throw grr::pe_loader_exception("Error reading relocation data.");

			buffer += difference;

			if (!WriteProcessMemory(process, reinterpret_cast<unsigned long*>(destination + base), &buffer, sizeof(buffer), nullptr))
				throw grr::pe_loader_exception("Error applying relocations data.");
		}
		break;
		case IMAGE_REL_BASED_ABSOLUTE:
		default:
			break;
		};
	}

	void pe_loader::set_section_permissions(const HANDLE process, const void* address, const unsigned long size, const unsigned long characteristics)
	{
		unsigned long permissions = 0;

		if (characteristics & IMAGE_SCN_MEM_EXECUTE)
			permissions = PAGE_EXECUTE;

		if (characteristics & IMAGE_SCN_MEM_READ)
			permissions = PAGE_READONLY;

		if (characteristics & IMAGE_SCN_MEM_WRITE)
			permissions = PAGE_READWRITE;

		if ((characteristics & IMAGE_SCN_MEM_EXECUTE) && permissions == PAGE_READWRITE)
			permissions = PAGE_EXECUTE_READWRITE;

		if ((characteristics & IMAGE_SCN_MEM_EXECUTE) && permissions == PAGE_READONLY)
			permissions = PAGE_EXECUTE_READ;

		if (!VirtualProtectEx(process, const_cast<void*>(address), size, permissions, &permissions))
			throw grr::pe_loader_exception("Error applying page protection.");
	}

	HMODULE pe_loader::get_library(const HANDLE process, const std::string& library_name)
	{
		//convert multibyte string to wchar string; required because module names granted via snapshot are wide-character.
		std::wstring name(library_name.begin(), library_name.end());

		const auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(process));

		if (snapshot == INVALID_HANDLE_VALUE)
			throw grr::pe_loader_exception("Error creating snapshot of remote process.");

		MODULEENTRY32 module_info;
		ZeroMemory(&module_info, sizeof(module_info));
		module_info.dwSize = sizeof(module_info);

		if (!Module32First(snapshot, &module_info))
			throw grr::pe_loader_exception("Error getting first module in remote process.");

		do
		{
			if (!_wcsicmp(module_info.szModule, name.c_str()))
				return module_info.hModule;
		} while (Module32Next(snapshot, &module_info));

		CloseHandle(snapshot);

		return nullptr;
	}

	//Works exactly like GetProcAddressA, only it takes a HANDLE, thus it can be used to get a procedure address from a remote process.
	void* pe_loader::get_remote_proc_address(const HANDLE process, const HMODULE module, const char* process_name)
	{
		IMAGE_DOS_HEADER dos_header;
		IMAGE_NT_HEADERS nt_headers;

		if (!ReadProcessMemory(process, module, &dos_header, sizeof(IMAGE_DOS_HEADER), nullptr))
			throw grr::pe_loader_exception("Error reading dos header from remote process.");

		if (!is_valid_dos_header(&dos_header))
			throw grr::pe_loader_exception("Invalid DOS Header.");

		if (!ReadProcessMemory(process, reinterpret_cast<void*>(dos_header.e_lfanew + reinterpret_cast<unsigned long>(module)), &nt_headers, sizeof(nt_headers), nullptr))
			throw grr::pe_loader_exception("Error reading image nt headers from remote process.");

		if (!is_valid_nt_headers(&nt_headers))
			throw grr::pe_loader_exception("Invalid PE Headers.");

		IMAGE_EXPORT_DIRECTORY export_directory;

		if (!ReadProcessMemory(process,
			reinterpret_cast<void*>(nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + reinterpret_cast<unsigned long>(module)),
			&export_directory, sizeof(IMAGE_EXPORT_DIRECTORY), nullptr))
			throw grr::pe_loader_exception("Error reading export directory from remote process.");

		std::unique_ptr<DWORD> function_rvas(new DWORD[export_directory.NumberOfFunctions]);

		if (!ReadProcessMemory(process, reinterpret_cast<void*>(export_directory.AddressOfFunctions + reinterpret_cast<unsigned long>(module)), function_rvas.get(), sizeof(DWORD) * export_directory.NumberOfFunctions, nullptr))
			throw grr::pe_loader_exception("Error reading export names table.");

		//Buffer used to store RVA of function, when (if) it is found.
		unsigned long rva_buffer = 0;

		//This is how MSDN defines the nature of GetProcAddress, so we will create getRemoteProcAddress in the same way. If the HIWORD is set, then sProcName is treated as a name, otherwise as an ordinal.
		if (HIWORD(process_name))
		{
			std::unique_ptr<DWORD> name_rvas(new DWORD[export_directory.NumberOfNames]);
			std::unique_ptr<WORD>  name_ordinal_rvas(new WORD[export_directory.NumberOfNames]);

			//Search for api via name
			if (!ReadProcessMemory(process, reinterpret_cast<void*>(export_directory.AddressOfNames + reinterpret_cast<unsigned long>(module)), name_rvas.get(), sizeof(DWORD) * export_directory.NumberOfNames, nullptr))
				throw grr::pe_loader_exception("Error reading export names table.");

			//Search for api via name
			if (!ReadProcessMemory(process, reinterpret_cast<void*>(export_directory.AddressOfNameOrdinals + reinterpret_cast<unsigned long>(module)), name_ordinal_rvas.get(), sizeof(WORD) * export_directory.NumberOfNames, nullptr))
				throw grr::pe_loader_exception("Error reading export ordinal table.");

			std::unique_ptr<char> name_buffer(new char[strlen(process_name) + 1]);
			for (unsigned int i = 0; i < export_directory.NumberOfNames; i++)
			{
				if (!ReadProcessMemory(process, reinterpret_cast<void*>(name_rvas.get()[i] + reinterpret_cast<unsigned long>(module)), name_buffer.get(), strlen(process_name) + 1, nullptr))
					throw grr::pe_loader_exception("Error reading import name.");

				if (!strcmp(name_buffer.get(), process_name))
					rva_buffer = function_rvas.get()[name_ordinal_rvas.get()[i]];
			}
		}
		else
		{
			rva_buffer = function_rvas.get()[reinterpret_cast<DWORD>(process_name)];
		}

		//Check to assure RVA was found, otherwise return 0 (error)
		if (!rva_buffer)
			return nullptr;

		//Check if it import is forwarded...
		if (rva_buffer >= nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress &&
			rva_buffer < nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
		{
			char forward_buffer[100];

			if (!ReadProcessMemory(process, reinterpret_cast<void*>(rva_buffer + reinterpret_cast<unsigned long>(module)), forward_buffer, sizeof(forward_buffer), nullptr))
				throw grr::pe_loader_exception("Error gathering information about forwarded symbol.");

			std::stringstream ss(forward_buffer);
			std::string library_name;
			std::string api_name;

			if (!std::getline(ss, library_name, '.'))
				throw grr::pe_loader_exception("Error parsing export forwarding.");

			library_name += ".dll";
			ss >> api_name;

			const auto remote_module = get_library(process, library_name);

			if (!remote_module)
				throw grr::pe_loader_exception("Error finding forwarded export; unable to find library forwarded to.");

			const auto address = get_remote_proc_address(process, remote_module, api_name.c_str());

			if (!address)
				throw grr::pe_loader_exception("Error finding forward API.");

			return address;
		}

		return reinterpret_cast<void*>(rva_buffer + reinterpret_cast<unsigned long>(module));
	}

	//Locates which section corresponds to an rva.
	const IMAGE_SECTION_HEADER* pe_loader::get_rva_section(const unsigned long rva, const IMAGE_NT_HEADERS* nt_headers)
	{
		const auto sections = IMAGE_FIRST_SECTION(const_cast<IMAGE_NT_HEADERS*>(nt_headers));

		for (unsigned int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++)
		{
			if (rva >= sections[i].VirtualAddress &&
				rva < sections[i].VirtualAddress + sections[i].Misc.VirtualSize)
				return &sections[i];
		}

		throw grr::pe_loader_exception("Unable to resolve RVA to its parent section.");
	}

	//Translates an RVA to a file offset.
	long pe_loader::rva_to_file_offset(const unsigned long rva, const IMAGE_NT_HEADERS* nt_headers)
	{
		const auto section = get_rva_section(rva, nt_headers);

		//Calculate differene in base of section data and base of section when mounted in to memory.
		const long delta = section->PointerToRawData - section->VirtualAddress;

		return rva + delta;
	}

	//Works the same as LoadLibraryA, only takes a HANDLE to which process the library is to be loaded in to.
	//This invokes LoadLibraryA in the remote process and returns its base address.
	HMODULE pe_loader::remote_load_library(const HANDLE process, const char* library_name)
	{
		void* memory = const_cast<char*>(library_name);
		if (HIWORD(library_name))
		{
			memory = VirtualAllocEx(process, nullptr, strlen(library_name), MEM_COMMIT, PAGE_READWRITE);

			if (!memory)
				throw grr::pe_loader_exception("Error injecting library, unable to allocate memory for library name.");

			if (!WriteProcessMemory(process, memory, library_name, strlen(library_name) + 1, nullptr))
				throw grr::pe_loader_exception("Error injecting library, unable to access memory allocated for library name.");
		}

		const auto thread = CreateRemoteThread(process, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA")), memory, 0, nullptr);

		if (!thread)
			throw grr::pe_loader_exception("Error creating remote thread at origin of LoadLibraryA");

		//Wait for thread to terminate
		if (WaitForSingleObject(thread, INFINITE) == WAIT_FAILED)
			throw grr::pe_loader_exception("Error occured while waiting for thread; remote LoadLibraryA invocation");

		HMODULE module = nullptr;

		//Get thread's exit code (eax), which is HMODULE of the loaded library.
		if (!GetExitCodeThread(thread, reinterpret_cast<DWORD*>(&module)))
			throw grr::pe_loader_exception("Error getting return code of remote thread.");

		CloseHandle(thread);

		return module;
	}

	unsigned long __stdcall invocation_stub(const unsigned long base_address)
	{
		typedef int(__stdcall *dll_main)(HINSTANCE, DWORD, LPVOID);

		const auto dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(base_address);
		const auto nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(dos_header->e_lfanew + base_address);

		const auto entry_point = nt_headers->OptionalHeader.AddressOfEntryPoint;
		const auto entry = reinterpret_cast<dll_main>(base_address + entry_point);

		entry(nullptr, DLL_PROCESS_ATTACH, nullptr);
		return base_address;
	}

	static void __declspec(noinline) invocation_stub_end()
	{ }

	HMODULE pe_loader::map_library(const HANDLE process) const
	{
		pfnNtSuspendProcess(process);
		auto library_base = VirtualAllocEx(process, reinterpret_cast<void*>(m_pFileNtHeaders->OptionalHeader.ImageBase), m_pFileNtHeaders->OptionalHeader.SizeOfImage, MEM_RESERVE, PAGE_READWRITE);

		if (!library_base)
		{
			//try loading at another address...
			library_base = VirtualAllocEx(process, nullptr, m_pFileNtHeaders->OptionalHeader.SizeOfImage, MEM_RESERVE, PAGE_READWRITE);

			if (!library_base)
				throw grr::pe_loader_exception("Error allocating enough memory for library in process.");
		}

		auto section_headers = IMAGE_FIRST_SECTION(m_pFileNtHeaders);

		//Commit memory for PE Headers.
		if (!VirtualAllocEx(process, library_base, m_pFileDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + m_pFileNtHeaders->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER), MEM_COMMIT, PAGE_READWRITE))
			throw grr::pe_loader_exception("Error committing memory for DOS header.");

		//Copy the PE headers in to memory, as to allow lookup of library exports.
		if (!WriteProcessMemory(process, library_base, m_pFileDosHeader, sizeof(IMAGE_DOS_HEADER), nullptr))
			throw grr::pe_loader_exception("Error copying dos header in to remote process.");

		if (!WriteProcessMemory(process, reinterpret_cast<void*>(reinterpret_cast<unsigned long>(library_base) + m_pFileDosHeader->e_lfanew), m_pFileNtHeaders, sizeof(IMAGE_NT_HEADERS), nullptr))
			throw grr::pe_loader_exception("Error copying NT headers in to remote process.");

		if (!WriteProcessMemory(process,
			reinterpret_cast<void*>(reinterpret_cast<unsigned long>(library_base) + m_pFileDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS)),
			section_headers, m_pFileNtHeaders->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER), nullptr))
			throw grr::pe_loader_exception("Error copying section headers in to remote process.");


		for (unsigned int i = 0; i < m_pFileNtHeaders->FileHeader.NumberOfSections; i++)
		{
			if (section_headers[i].Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
				continue;

			void* pFileSectionAddress = reinterpret_cast<void*>(section_headers[i].PointerToRawData + reinterpret_cast<unsigned long>(file_view_));
			void* pMemorySectionAddress = reinterpret_cast<void*>(section_headers[i].VirtualAddress + reinterpret_cast<unsigned long>(library_base));

			unsigned long ulSectionSize = section_headers[i].SizeOfRawData;

			//Commit the memory we previously reserved for this section.
			if (VirtualAllocEx(process, pMemorySectionAddress, section_headers[i].Misc.VirtualSize, MEM_COMMIT, PAGE_READWRITE) != pMemorySectionAddress)
				throw grr::pe_loader_exception("Error commiting memory for section.");

			if (ulSectionSize > 0)
			{
				if (!WriteProcessMemory(process, pMemorySectionAddress, pFileSectionAddress, ulSectionSize, nullptr))
					throw grr::pe_loader_exception("Error copying section to remote process.");
			}
		}

		// Resolve image imports and setup the IAT
		if (m_pFileNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
		{
			IMAGE_IMPORT_DESCRIPTOR* pImportDescriptors = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(rva_to_file_offset(m_pFileNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, m_pFileNtHeaders) + reinterpret_cast<unsigned long>(file_view_));
			for (unsigned int i = 0; pImportDescriptors[i].FirstThunk; i++)
			{
				IMAGE_THUNK_DATA* pInts = reinterpret_cast<IMAGE_THUNK_DATA*>(reinterpret_cast<unsigned long>(file_view_) + rva_to_file_offset(pImportDescriptors[i].OriginalFirstThunk, m_pFileNtHeaders));
				IMAGE_THUNK_DATA* pIat = reinterpret_cast<IMAGE_THUNK_DATA*>(reinterpret_cast<unsigned long>(library_base) + pImportDescriptors[i].FirstThunk);

				HMODULE hImportLib = remote_load_library(process, reinterpret_cast<char*>(file_view_) + rva_to_file_offset(pImportDescriptors[i].Name, m_pFileNtHeaders));
				//std::cout << "File: " << reinterpret_cast<char*>(m_pFileView) + rvaToFileOffset(pImportDescriptors[i].Name, m_pFileNtHeaders) << std::endl;

				for (unsigned int x = 0; pInts[x].u1.Function != 0; x++)
				{
					unsigned long ulImportNameOrdinal = 0;

					if (pInts[x].u1.Function & (1 >> 31))
					{
						//if MSB is set, it is an ordinal.
						ulImportNameOrdinal = pInts[x].u1.Function & ~(1 >> 31);
					}
					else
					{
						IMAGE_IMPORT_BY_NAME* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(reinterpret_cast<unsigned long>(file_view_) + rva_to_file_offset(pInts[x].u1.Function, m_pFileNtHeaders));
						ulImportNameOrdinal = reinterpret_cast<unsigned long>(pImport->Name);
					}

					//std::cout << reinterpret_cast<const char*>(ulImportNameOrdinal) << " loaded into target process." << std::endl;
					void* pProcAddress = get_remote_proc_address(process, hImportLib, reinterpret_cast<const char*>(ulImportNameOrdinal));

					if (!pProcAddress)
						throw grr::pe_loader_exception("Error finding import.");

					if (!WriteProcessMemory(process, &pIat[x], &pProcAddress, sizeof(void*), nullptr))
						throw grr::pe_loader_exception("Error writing to remote IAT.");
				}
			}
		}

		//Do relocations described in the Relocations data directory if required.
		if (reinterpret_cast<unsigned long>(library_base) != m_pFileNtHeaders->OptionalHeader.ImageBase && m_pFileNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)
		{
			auto base_relocations = reinterpret_cast<IMAGE_BASE_RELOCATION*>(rva_to_file_offset(m_pFileNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, m_pFileNtHeaders) + reinterpret_cast<unsigned long>(file_view_));
			for (auto current_relocation = base_relocations;
				reinterpret_cast<unsigned long>(current_relocation) - reinterpret_cast<unsigned long>(base_relocations) < m_pFileNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
				current_relocation = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<unsigned long>(current_relocation) + current_relocation->SizeOfBlock))
			{
				long difference = reinterpret_cast<unsigned long>(library_base) - m_pFileNtHeaders->OptionalHeader.ImageBase;
				auto base = reinterpret_cast<unsigned long>(library_base) + current_relocation->VirtualAddress;

				auto relocation_offsets = reinterpret_cast<WORD*>(reinterpret_cast<unsigned long>(current_relocation) + sizeof(IMAGE_BASE_RELOCATION));

				for (unsigned int i = 0; i < current_relocation->SizeOfBlock / sizeof(WORD); i++)
					calculate_relocation(process, difference, base, relocation_offsets[i]);
			}
		}
		//After code relocations, we can apply the proper page permissions.
		for (unsigned int i = 0; i < m_pFileNtHeaders->FileHeader.NumberOfSections; i++)
		{
			if (section_headers[i].Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
				continue;

			auto memory_section_address = reinterpret_cast<void*>(section_headers[i].VirtualAddress + reinterpret_cast<unsigned long>(library_base));
			set_section_permissions(process, memory_section_address, section_headers[i].Misc.VirtualSize, section_headers[i].Characteristics);
		}

		auto stub_size = 45; //std::abs(reinterpret_cast<long>(&invocation_stub_end) - reinterpret_cast<long>(&invocation_stub));

		std::cout << "Stub location: 0x" << std::hex << reinterpret_cast<unsigned long>(&invocation_stub) << std::dec << std::endl;
		std::cout << "Stub end location: 0x" << std::hex << reinterpret_cast<unsigned long>(&invocation_stub_end) << std::dec << std::endl;
		std::cout << "Stub size: 0x" << std::hex << stub_size << std::dec << std::endl;

		auto remote_invocation_stub = VirtualAllocEx(process, nullptr, stub_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		if (!remote_invocation_stub)
			throw grr::pe_loader_exception("Error allocating memory for remote dllmain invocation stub.");

		if (!WriteProcessMemory(process, remote_invocation_stub, static_cast<void*>(invocation_stub), stub_size, nullptr))
			throw grr::pe_loader_exception("Error copying dllmain invocation stub into remote process.");

		pfnNtResumeProcess(process);
		auto thread = CreateRemoteThread(process, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(remote_invocation_stub), static_cast<void*>(library_base), 0, nullptr);

		if (WaitForSingleObject(thread, INFINITE) == WAIT_FAILED)
			throw grr::pe_loader_exception("Error waiting for remote thread on dllmain invocation stub.");

		DWORD exit_code = 1337;

		//Get thread's exit code (eax), which is HMODULE of the loaded library.
		if (!GetExitCodeThread(thread, reinterpret_cast<DWORD*>(&exit_code)))
			throw grr::pe_loader_exception("Error getting return code of remote thread.");

		std::cout << "Library base: 0x" << std::hex << library_base << std::dec << std::endl;
		std::cout << "Thread exit code: 0x" << std::hex << exit_code << std::dec << std::endl;

		if (!VirtualFreeEx(process, remote_invocation_stub, 0, MEM_RELEASE))
			throw grr::pe_loader_exception("Error freeing dllmain invocation stub.");

		CloseHandle(thread);
		return reinterpret_cast<HMODULE>(library_base);
	}

	HMODULE pe_loader::load_library(const std::string& library_name, const HANDLE process)
	{
		const auto remote_library = get_library(process, library_name);
		if (remote_library)
			return remote_library;

		pe_loader lib(library_name);
		return lib.map_library(process);
	}

	HMODULE pe_loader::load_memory_library(const void* source_image, const std::string& library_name, const HANDLE process)
	{
		const auto remote_library = get_library(process, library_name);
		if (remote_library)
			return remote_library;

		pe_loader lib(source_image);
		return lib.map_library(process);
	}
}