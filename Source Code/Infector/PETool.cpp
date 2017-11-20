#include "stdafx.h"
#include "PETool.h"

//Constructor
PETool::PETool()
{
   this->pe_LoadLibraryAddr = 0;
   this->pe_GetProcAddressAddr = 0;
   this->PEimage = NULL;
   this->fileSize = 0;
   this->pe_sections_count = 0;
   (void) memset( &this->p_dos, 0x00, sizeof(this->p_dos) );
   (void) memset( &this->pe_sections, 0x00, sizeof(this->pe_sections) );

   this->buff  = ::HeapCreate( NULL, 10 * 1024 * 1024, 0 );
}
//Destructor
PETool::~PETool()
{
   (void) ::HeapDestroy(this->buff);
}
//Load PE file to buffer//
BOOL PETool::LoadFile(char *file)
{
	HANDLE hFile = NULL; //PE handle
	DWORD dwBytesRead = 0;//used for read file

	//if file dosn't exist
	if (file == NULL)
		return FALSE;

	//create a Handle for PE file
	hFile = ::CreateFile(file,
		GENERIC_READ,
		FILE_SHARE_WRITE | FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;

	//get PE size
	this->fileSize = ::GetFileSize(hFile, NULL);

	//check if size is legal
	if (this->fileSize < sizeof(IMAGE_NT_HEADERS))
		goto CPETH_LF_ERROR;

	//make buffer for PE file with file size and check it created succesfully
	this->PEimage = this->allocate(this->fileSize);
	if (!this->PEimage)
		goto CPETH_LF_ERROR;

	//Reads data from the PE buffer we created
	(void) ::ReadFile(hFile, this->PEimage, this->fileSize, &dwBytesRead, NULL);

	//if some error accord when reading file
	if (dwBytesRead != this->fileSize)
		goto CPETH_LF_ERROR;

	//load DOS section to DOSDATA.header and check if it is legel
	(void)memcpy(&this->p_dos.header, this->PEimage, sizeof(IMAGE_DOS_HEADER)); //save in DOSDATA.header the PE dos section header
	if (this->p_dos.header.e_magic != IMAGE_DOS_SIGNATURE)
		goto CPETH_LF_ERROR;

	//if for some reason stub is not empty then empty it
	if (this->p_dos.stub)
		this->free(this->p_dos.stub);

	//get stub size
	this->p_dos.stub_size = this->p_dos.header.e_lfanew - sizeof(IMAGE_DOS_HEADER);

	//if stub size is positive insert dos PE dos stub to buffer
	if (this->p_dos.stub_size)
	{
		this->p_dos.stub = this->allocate(this->p_dos.stub_size);
		(void)memcpy(this->p_dos.stub, this->PEimage + sizeof(IMAGE_DOS_HEADER), this->p_dos.stub_size);
	}
	else
		this->p_dos.stub = NULL;


	//load NT headers to DOSDATA.header and check if it is legel
	(void)memcpy(&this->p_nt, this->PEimage + this->p_dos.header.e_lfanew, sizeof(IMAGE_NT_HEADERS));
	if (this->p_nt.Signature != IMAGE_NT_SIGNATURE)
		goto CPETH_LF_ERROR;

	// free sections from buffer if not empty
	this->free_loaded_sections();

	//get PEs number of sections
	this->pe_sections_count = this->p_nt.FileHeader.NumberOfSections;

	//copy all of PE sections to our PE buffer
	IMAGE_SECTION_HEADER *section_pointer = NULL;
	section_pointer = (IMAGE_SECTION_HEADER *)(this->PEimage + this->p_dos.header.e_lfanew + sizeof(IMAGE_NT_HEADERS)); //pointer to sections part.
	DWORD i = 0; //counter to go thru all sections
	//iterate through all sections and save them to buffer
	for (i = 0; i < this->pe_sections_count; i++)
	{
		(void)memcpy(&this->pe_sections[i].header, section_pointer, sizeof(IMAGE_SECTION_HEADER)); //copy pointer of section to buffer
		this->pe_sections[i].data = this->allocate(this->align_to(this->pe_sections[i].header.SizeOfRawData, this->p_nt.OptionalHeader.FileAlignment)); //create buffer for section data with alignment
		(void)memcpy(this->pe_sections[i].data,	this->PEimage + this->pe_sections[i].header.PointerToRawData, this->pe_sections[i].header.SizeOfRawData); //copy section data to PE buffer
		section_pointer++;
	}

	//save original entry point
	this->pe_ep = this->p_nt.OptionalHeader.AddressOfEntryPoint + this->p_nt.OptionalHeader.ImageBase;

	this->find_api_calls();

	//free PE buffer from memory
	this->free(this->PEimage);
	this->PEimage = NULL;

	//close PE Handle file
	(void) ::CloseHandle(hFile);

	return TRUE;

	//if any error occurred then rollback and free memory
CPETH_LF_ERROR:

	if (this->PEimage)
		this->free(this->PEimage);

	(void) ::CloseHandle(hFile);

	return FALSE;
}
//take all section and new addded section and write to disk
BOOL PETool::SaveFile(char *file)
{
	HANDLE hFile = NULL; //PE handle
	DWORD dwBytesWritten = 0;
	IMAGE_SECTION_HEADER *lpSection = NULL;

	if (file == NULL || this->pe_sections_count == 0)
		return FALSE;
	//if hFile is pointing to somthing- close it
	if (hFile)
		(void) ::CloseHandle(hFile);
	//create handle for read and write
	hFile = ::CreateFile(file,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_WRITE | FILE_SHARE_READ,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;
	//get size of of new section
	DWORD newSectionSize = this->pe_sections[this->pe_sections_count - 1].header.PointerToRawData + this->pe_sections[this->pe_sections_count - 1].header.SizeOfRawData;
	this->PEimage = this->allocate(newSectionSize);

	//Align all sections in pe buffer
	DWORD  counter = 0;
	for (counter = 0; counter < this->pe_sections_count; counter++)
	{
		this->pe_sections[counter].header.VirtualAddress = this->align_to(this->pe_sections[counter].header.VirtualAddress, this->p_nt.OptionalHeader.SectionAlignment);
		this->pe_sections[counter].header.PointerToRawData = this->align_to(this->pe_sections[counter].header.PointerToRawData, this->p_nt.OptionalHeader.FileAlignment);
		this->pe_sections[counter].header.SizeOfRawData = this->align_to(this->pe_sections[counter].header.SizeOfRawData, this->p_nt.OptionalHeader.FileAlignment);
	}
	this->p_nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
	this->p_nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;
	this->p_nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = 0;
	this->p_nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = 0;
	this->p_nt.OptionalHeader.SizeOfImage = this->pe_sections[this->pe_sections_count - 1].header.VirtualAddress + this->pe_sections[this->pe_sections_count - 1].header.Misc.VirtualSize;

	//start copying all info we stored to Host PE file
	//Copy DOS Info
	(void)memcpy(this->PEimage, &this->p_dos.header, sizeof(IMAGE_DOS_HEADER));
	//Copy DOS Stub
	if (this->p_dos.stub_size)
		(void) memcpy(this->PEimage + sizeof(IMAGE_DOS_HEADER), this->p_dos.stub, this->p_dos.stub_size);
	//Copy NT Headers
	(void)memcpy(this->PEimage + this->p_dos.header.e_lfanew, &this->p_nt, sizeof(IMAGE_NT_HEADERS));
	// iterate though section headers and copy them
	DWORD FirstSec = this->p_dos.header.e_lfanew + sizeof(IMAGE_NT_HEADERS);
	for (counter = 0; counter < this->pe_sections_count; counter++)
		(void) memcpy(this->PEimage + FirstSec + counter * sizeof(IMAGE_SECTION_HEADER), &this->pe_sections[counter].header,	sizeof(IMAGE_SECTION_HEADER));
	//Copy Sections Data
	for (counter = 0; counter < this->pe_sections_count; counter++)
		(void) memcpy(this->PEimage + this->pe_sections[counter].header.PointerToRawData, this->pe_sections[counter].data, this->pe_sections[counter].header.SizeOfRawData);

	(void) ::WriteFile(hFile, this->PEimage, newSectionSize, &dwBytesWritten, NULL); //save data
	(void) ::FlushFileBuffers(hFile);//empty handle
	(void) ::CloseHandle(hFile);//close handle

	if (this->PEimage)
		this->free(this->PEimage); //free pe buffer 

	return TRUE;
}
//create buffer
BYTE *PETool::allocate(DWORD _size)
{
	//if not empty then empty it.
    if ( !this->buff ) 
        return (BYTE *)NULL;

    return (BYTE *)::HeapAlloc( this->buff, HEAP_ZERO_MEMORY | HEAP_NO_SERIALIZE, _size );
}
//free buffer
void PETool::free(BYTE *_lpMem)
{
    if ( !this->buff ) 
        return;

    (void) ::HeapFree( this->buff, HEAP_NO_SERIALIZE, _lpMem ); 
}
//frees the Sections buffer 
void PETool::free_loaded_sections(void)
{
    DWORD count = 0;
    if ( !this->pe_sections_count )
        return;

    for ( count = 0; count < this->pe_sections_count; count++ )
        if ( this->pe_sections[count].data )
            this->free(this->pe_sections[count].data);

    this->pe_sections_count = 0;
    (void) memset( &this->pe_sections, 0x00, sizeof(this->pe_sections) );
}
//make section alignments since the loader allocates memory in pages
inline DWORD PETool::align_to( DWORD _size, DWORD _base_size )
{
	return ( ((_size + _base_size-1) / _base_size) * _base_size );
}
//search for kernal32.dll and find get LoadLibraryA and GetProcAdress
void PETool::find_api_calls(void)
{
	char *dllName = NULL;
	DWORD dll_import = 0;
	DWORD Thunk = 0; //get dll thunk address
	const IMAGE_IMPORT_DESCRIPTOR *p_Imp = NULL; //pointer to current dll import
	const IMAGE_THUNK_DATA *itAPI = NULL; //iterator to search through kernal32.dll
	const IMAGE_IMPORT_BY_NAME *name_import = NULL;

	//get RVA to first section in Import directory
	dll_import = this->rva_to_offset(this->p_nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	if ( !dll_import )
	   return;

	//iterator pointer to current dll import to find kernal32.dll
	p_Imp = (IMAGE_IMPORT_DESCRIPTOR *)((DWORD)this->PEimage + dll_import);      
	while (p_Imp->Name )
	{
		//get name of current dll
		dllName = (char *)((DWORD)(DWORD)this->PEimage + this->rva_to_offset(p_Imp->Name));
		//iterate untill you find kernal32.dll
		if ( stricmp( dllName, "kernel32.dll" ) )
		{
			p_Imp++;
			continue;
		}

		//get originalFirstThunk, if it doesn't exist get first thunk
		//original first thunk points to phisical point of kernal32 on disk, first thunk points to IAT
		//In the case, the First Original Thunk is not present; the First Thunks refers to where the Hint data and the Function Name data are located
		Thunk = (p_Imp->OriginalFirstThunk ? p_Imp->OriginalFirstThunk : p_Imp->FirstThunk);
		
		//get offset of thunk in virtual memory
		itAPI = (IMAGE_THUNK_DATA *)((DWORD)this->PEimage + this->rva_to_offset(Thunk));
		//get address to api functions
		Thunk = p_Imp->FirstThunk;
		//now that we have kernal32 import table address we look for API function: LoadLibraryA and GetProcAdress, and store them.
		while (itAPI->u1.AddressOfData )
		{
			name_import = (IMAGE_IMPORT_BY_NAME *)((DWORD)this->PEimage + this->rva_to_offset((DWORD)itAPI->u1.AddressOfData));
			if ( !stricmp( (char *)name_import->Name, "LoadLibraryA" ) )
				this->pe_LoadLibraryAddr = this->p_nt.OptionalHeader.ImageBase + Thunk;
			else if ( !stricmp( (char *)name_import->Name, "GetProcAddress" ) )
				this->pe_GetProcAddressAddr = this->p_nt.OptionalHeader.ImageBase + Thunk;
			itAPI++;
			Thunk += sizeof(DWORD);
		}
		break;
	}
	return;
}
//turn RVA to offset, by taking-> (raw data - virtual address)
DWORD PETool::rva_to_offset(DWORD _rva)
{
   BOOL bFound = FALSE;
   DWORD counter = 0;

   for ( counter = 0; counter < this->pe_sections_count; counter++ )
   {
		if( this->pe_sections[counter].header.VirtualAddress && _rva <= (this->pe_sections[counter].header.VirtualAddress + this->pe_sections[counter].header.SizeOfRawData) )
		{
			bFound = TRUE;
			break;
		}
   }
   if ( !bFound ) 
      return (DWORD)NULL;

   return (_rva + this->pe_sections[counter].header.PointerToRawData - this->pe_sections[counter].header.VirtualAddress);
}
//add new section to our PE buffer
void PETool::AddCodeSection( char *newSectionName, BYTE *sectionToInsert, DWORD newSectionSize, DWORD newEntryPoint )
{
	DWORD lastSection = this->pe_sections_count; //get ammount of sections from pe buffer

	//make sure we have name and section to insert
	if ( newSectionName == NULL || sectionToInsert == NULL )
		return;

	//set up new section parameters:
	DWORD sectionSize = newSectionSize;
	this->pe_sections[lastSection].data = this->allocate( this->align_to(sectionSize, this->p_nt.OptionalHeader.FileAlignment) );
	this->pe_sections[lastSection].header.PointerToRawData = this->align_to( this->pe_sections[lastSection-1].header.PointerToRawData + this->pe_sections[lastSection-1].header.SizeOfRawData, this->p_nt.OptionalHeader.FileAlignment ); 
	this->pe_sections[lastSection].header.VirtualAddress   = this->align_to( this->pe_sections[lastSection-1].header.VirtualAddress + this->pe_sections[lastSection-1].header.Misc.VirtualSize, this->p_nt.OptionalHeader.SectionAlignment );
	this->pe_sections[lastSection].header.SizeOfRawData	  = this->align_to( sectionSize, this->p_nt.OptionalHeader.FileAlignment );
	this->pe_sections[lastSection].header.Misc.VirtualSize = sectionSize;
	this->pe_sections[lastSection].header.Characteristics  = 0xE0000040; //make section readable, writable, executable, contains initialized data

	//copy new section name to pe array buffer
	(void) memcpy( this->pe_sections[lastSection].header.Name, newSectionName, (size_t)strlen(newSectionName) );
	//update section count
	this->p_nt.FileHeader.NumberOfSections++;
	this->pe_sections_count++; 
	//copy all data of new section to pe array buffer
	(void) memcpy( this->pe_sections[lastSection].data, sectionToInsert, newSectionSize );
	//change entry point and store it in our nt buffer
	this->p_nt.OptionalHeader.AddressOfEntryPoint = this->pe_sections[lastSection].header.VirtualAddress + newEntryPoint; 
}
DWORD PETool::get_section_index(DWORD _rva)
// * ----------------------------------------------------------------------------* 
{
	DWORD iC = 0;

	for (iC = 0; iC < this->pe_sections_count; iC++)
	{
		if (this->pe_sections[iC].header.VirtualAddress && _rva <= (this->pe_sections[iC].header.VirtualAddress + this->pe_sections[iC].header.SizeOfRawData))
			return iC;
	}

	return -1;
}

