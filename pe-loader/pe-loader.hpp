#pragma once

#include "stdafx.h"

namespace grr
{
	class pe_loader
	{
		std::string library_name_;

		HANDLE file_map_;
		HANDLE file_;
		void*  file_view_;

		IMAGE_NT_HEADERS* m_pFileNtHeaders;
		IMAGE_DOS_HEADER* m_pFileDosHeader;

		void init(const void* view, HANDLE file = nullptr, HANDLE file_map = nullptr);

	protected:
		explicit pe_loader(const std::string& library_name);
		explicit pe_loader(const void* source_image);
		virtual ~pe_loader();

		static inline bool is_valid_nt_headers(const IMAGE_NT_HEADERS* nt_headers);
		static inline bool is_valid_dos_header(const IMAGE_DOS_HEADER* dos_header);

		static void calculate_relocation(HANDLE process, long difference, unsigned long base, WORD offset);
		static void set_section_permissions(HANDLE process, const void* address, unsigned long size, unsigned long characteristics);

		static HMODULE get_library(HANDLE process, const std::string& library_name);
		static void*   get_remote_proc_address(HANDLE process, HMODULE module, const char* process_name);

		static const IMAGE_SECTION_HEADER* get_rva_section(unsigned long rva, const IMAGE_NT_HEADERS* nt_headers);
		static long	 rva_to_file_offset(unsigned long rva, const IMAGE_NT_HEADERS* nt_headers);

		static HMODULE remote_load_library(HANDLE process, const char* library_name);
		HMODULE map_library(HANDLE process) const;

	public:
		static HMODULE load_library(const std::string& library_name, HANDLE process = GetCurrentProcess());
		static HMODULE load_memory_library(const void* source_image, const std::string& library_name = std::string(), HANDLE process = GetCurrentProcess());
	};
}