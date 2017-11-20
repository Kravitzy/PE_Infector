#pragma once

#include <windows.h>
#include <winnt.h>

#define PE_MAX_DATA_SECTIONS 32

//struct to store Dos Header info
typedef struct _PE_DOS_DATA_
{
	IMAGE_DOS_HEADER header;
	DWORD			 stub_size;
	BYTE			*stub;
} DOSSECTION;
//struct to store PE sections
typedef struct _PE_SECTION_
{
    IMAGE_SECTION_HEADER  header;
    BYTE                 *data;
} PESECTION;

class PETool
{
    private:

	  // PE buffer manage:
      HANDLE buff; //a buffer to store info
      DWORD  fileSize; //PE size
      BYTE  *PEimage; //pointer to PE base

      DOSSECTION p_dos; //holder struct for Dos Header
      IMAGE_NT_HEADERS  p_nt; //holder for NT Header
      DWORD     pe_sections_count; //ammount of sections in PE
      PESECTION pe_sections[PE_MAX_DATA_SECTIONS]; //array to store all PE sections
	
	  DWORD   pe_ep;	// entry point	
	  DWORD   pe_LoadLibraryAddr; // PE kernal32.dll LoadLibrary address
	  DWORD	  pe_GetProcAddressAddr; // PE kernal32.dll GetProcAddress address



    public:

      PETool();
     ~PETool();
	  BOOL LoadFile(char *file);
      BOOL SaveFile(char *file);
      DWORD Get_LoadLibraryAddr(void)
      { 
         return this->pe_LoadLibraryAddr; 
      }
      DWORD Get_GetProcAddressAddr(void)
      { 
         return this->pe_GetProcAddressAddr; 
      }
      DWORD Get_ExecEntryPoint(void)
      { return this->pe_ep; }
      void AddCodeSection( char *_name, BYTE *_section, DWORD _section_size, DWORD _entry_point_offset );
	  inline BYTE *allocate(DWORD _size);
	  inline void free(BYTE *_lpMem);
	  inline void free_loaded_sections(void);
	  inline void find_api_calls(void);
	  inline DWORD rva_to_offset(DWORD _rva);
	  inline DWORD align_to(DWORD _size, DWORD _base_size);
	  inline DWORD get_section_index(DWORD _rva);
};

