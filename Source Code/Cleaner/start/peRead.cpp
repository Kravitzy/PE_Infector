#include<stdio.h>
#include<windows.h>
#include<time.h>
#include<tchar.h>
#include "peRead.h"


PE::PE() {

}
PE::~PE() {

}



bool PE::RemoveSection(char *filepath) {

	HANDLE file = CreateFileA(filepath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL); //open file
	if (file == INVALID_HANDLE_VALUE)
		return false;
	DWORD fileSize = GetFileSize(file, NULL);
	//so we know how much buffer to allocate
	BYTE *pByte = new BYTE[fileSize];
	DWORD dw;
	//read the entire file,so we can use the PE information
	ReadFile(file, pByte, fileSize, &dw, NULL);

	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pByte; //pointer to dos section
	if (dos->e_magic != IMAGE_DOS_SIGNATURE)
		return false; //invalid PE
	PIMAGE_FILE_HEADER FH = (PIMAGE_FILE_HEADER)(pByte + dos->e_lfanew + sizeof(DWORD)); //pointer to PE header
	PIMAGE_OPTIONAL_HEADER OH = (PIMAGE_OPTIONAL_HEADER)(pByte + dos->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)); //pointer to optional header
	PIMAGE_SECTION_HEADER SH = (PIMAGE_SECTION_HEADER)(pByte + dos->e_lfanew + sizeof(IMAGE_NT_HEADERS)); //pointer to section header
	
	int pointer = SH[FH->NumberOfSections - 1].PointerToRawData + SH[FH->NumberOfSections - 1].SizeOfRawData;//save pointer to point to begining of last section. (subtract by 1 to get end of file)
	OH->SizeOfImage = SH[FH->NumberOfSections-1].VirtualAddress; //update size
	FH->NumberOfSections -= 1;
	SetFilePointer(file, 0, NULL, FILE_BEGIN);
	//and finaly,we add all the modifications to the file
	WriteFile(file, pByte, fileSize, &dw, NULL);
	SetFilePointer(file, pointer-1, NULL, FILE_BEGIN); //(subtract by one to get end of new last section)
	SetEndOfFile(file);

	CloseHandle(file);
	return true;
}

bool PE::ChangeOEP(char * filepath, const char* password)
{
	HANDLE file = CreateFileA(filepath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL); //open file
	if (file == INVALID_HANDLE_VALUE)
		return false;
	DWORD filesize = GetFileSize(file, NULL);
	BYTE *pByte = new BYTE[filesize]; //store PE in buffer
	DWORD dw;
	ReadFile(file, pByte, filesize, &dw, NULL);
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pByte;  //pointer to dos section
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(pByte + dos->e_lfanew); //pointer to PE section
	//since we added a new section, we must get to the last section to insert our data
	PIMAGE_SECTION_HEADER first = IMAGE_FIRST_SECTION(nt);
	PIMAGE_SECTION_HEADER last = first + (nt->FileHeader.NumberOfSections - 1);

	BYTE buff[10]; //store password
	SetFilePointer(file, last->PointerToRawData+16, NULL, FILE_BEGIN);
	ReadFile(file, &buff, sizeof(DWORD), &dw, NULL);
	bool eql = !strcmp(password, (const char *)buff);
	if (!eql)  // password isn't correct
	{
		printf("\n password incorect");
		return false;
	}


	SetFilePointer(file, last->PointerToRawData, NULL, FILE_BEGIN);
	BYTE buff2[10]; //store OEP from file
	ReadFile(file, &buff2, sizeof(DWORD), &dw, NULL);
	DWORD OEP = *(DWORD*)buff2 - nt->OptionalHeader.ImageBase; 
	//nt->OptionalHeader.AddressOfEntryPoint = OEP; //for some reason this didn't work, I had to find a way to work around it
	CloseHandle(file);//close

	// changed the entry point this way instead
	IMAGE_DOS_HEADER *pHead;
    pHead = new IMAGE_DOS_HEADER;
    FILE *file2 = fopen(filepath,"r+b");
    if(!file2)
        return false;
    fread(pHead,sizeof(IMAGE_DOS_HEADER),1,file2);
    if(pHead->e_magic != IMAGE_DOS_SIGNATURE)
        return false;
    long peHeader = pHead->e_lfanew;
    long peOptHeader = peHeader + 4 + sizeof(IMAGE_FILE_HEADER);
    fseek(file2,peOptHeader,SEEK_SET);
    IMAGE_OPTIONAL_HEADER *pOpt;
    pOpt = new IMAGE_OPTIONAL_HEADER;
    fread(pOpt,sizeof(IMAGE_OPTIONAL_HEADER),1,file2);
    pOpt->AddressOfEntryPoint = OEP;
    fseek(file2,peOptHeader,SEEK_SET);
    fwrite(pOpt,sizeof(IMAGE_OPTIONAL_HEADER),1,file2);
    fclose(file2);
    delete pOpt;
    delete pHead;
	return TRUE;
}

DWORD PE::align(DWORD size, DWORD align, DWORD addr) {
	//align according to PE Alignment
	if (!(size % align))
		return addr + size;
	return addr + (size / align + 1) * align;
}


