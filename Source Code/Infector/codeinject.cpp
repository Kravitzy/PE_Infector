
#include "codeinject.h"

//New PE Section
BYTE newEPsection[_MAX_SECTION_SIZE];
//data needed for new PE section
BYTE newEPdata[_MAX_SECTION_DATA_SIZE_];
//code that will link to newEPdata
BYTE newEPcode[_MAX_SEC_SECTION_DATA_SIZE_];

int main(int argc, char* argv[])
{

   PETool *pe = new PETool();

   //Get password enterd
   char *password = NULL;
   password = argv[2];

   CopyFile(argv[1], "originalCopy.exe", false);

  
   //Load the PE file:
   if ( !pe->LoadFile(argv[1]) )
   {
      printf( "\nError: Can not load %s", argv[1] );
      exit(-1);
   }

   // Check if LoadLibrary and GetProcAddress exist in PE host.
   if ( pe->Get_LoadLibraryAddr() == 0 || pe->Get_GetProcAddressAddr() == 0 )
   {
      printf( "\nError: Can not find LoadLibrary and/or GetProcAddress entry points" );
      exit(-2);
   }

   //build new code to insert with password:
   fill_data_areas(pe, password);

   
   //make room for new section to insert
   UINT OffSet = 0;
   //add data filled to newEPsection and write
   (void) memset( newEPsection, 0x00, sizeof(newEPsection) );
   (void) memcpy( &newEPsection[OffSet], newEPdata, sizeof(newEPdata) );
   //Add new NewEntryPoint Code
   OffSet += sizeof(newEPdata);
   (void) memcpy( &newEPsection[OffSet], (BYTE *)NewEntryPoint, (DWORD)NewEntryPoint_End - (DWORD)NewEntryPoint );
   //Add data for code section
   OffSet += ((DWORD)NewEntryPoint_End - (DWORD)NewEntryPoint);
   (void) memcpy( &newEPsection[OffSet], newEPcode, sizeof(newEPcode) );
   //Add new PwdWindow Code
   OffSet += sizeof(newEPcode);
   (void) memcpy( &newEPsection[OffSet], (BYTE *)PwdWindow, (DWORD)PwdWindow_End - (DWORD)PwdWindow );

   //add new section and store all new information in pe buffer
 	pe->AddCodeSection( ".proj", newEPsection, _MAX_SECTION_SIZE, _MAX_SECTION_DATA_SIZE_ );   

	//take all newly added code and overite original code
 	pe->SaveFile(argv[1]);
	
	return 0;
}


void fill_data_areas(PETool *pe, char *password)
{
	DWORD OriginalEntryPoint = pe->Get_ExecEntryPoint(); //get  original entry point
	DWORD LoadLibraryAddr = pe->Get_LoadLibraryAddr(); //get pe LoadLibrary API
	DWORD GetProcAddress = pe->Get_GetProcAddressAddr(); //get pe ProcAddress
	BYTE  pass[12];            // Password maximum size

	//make place for new code data
	(void)memset(newEPdata, 0x00, sizeof(newEPdata));
	(void)memset(newEPcode, 0x00, sizeof(newEPcode));

	//put OEP in newCodeData[0] 
	(void)memcpy(newEPdata, &OriginalEntryPoint, sizeof(DWORD));  // offset = 0
	//put LoadLibrary in newCodeData[4]
	(void)memcpy(&newEPdata[4], &LoadLibraryAddr, sizeof(DWORD));     // offset = 4
	//put GetProcAddress in newCodeData[4]
	(void)memcpy(&newEPdata[8], &GetProcAddress, sizeof(DWORD));  // offset = 8

	//save size of newSection newCodeData[12]
	DWORD EPSize = 0;
	EPSize = (DWORD)NewEntryPoint_End - (DWORD)NewEntryPoint;
	(void)memcpy(&newEPdata[12], &EPSize, sizeof(DWORD));

	//save user input password in newEPdata[16]
	(void)memset(pass, 0x00, sizeof(pass));
	(void)strcpy((char *)pass, password);
	(void)memcpy(&newEPdata[16], pass, 12);  // offset = 16

	//Mark end of data area with <E>
	(void)memcpy(&newEPdata[_MAX_SECTION_DATA_SIZE_ - 3], "<E>", 3);

	//Mark end of code area
	(void)memcpy(&newEPcode[_MAX_SEC_SECTION_DATA_SIZE_ - 3], "<E>", 3);

	//import string to be used by injected code
	DWORD i = _OFFSET_STRINGS; //get offet of strings data section
	for (int counter = 0; newCode_strings[counter]; counter++)
	{
		(void)memcpy(&newEPdata[i], newCode_strings[counter], strlen(newCode_strings[counter])); //copy string to newEPdata to string section in new code
		i += ((UINT)strlen(newCode_strings[counter]) + 1);
	}

	//import all DLLs and Functions to be used by injected code
	i = _OFFSET_DLL_NAMES; //get offset of DLL data section
	DWORD j = _OFFSET_FUNCTION_NAMES; //get offset of API functions in data section
	for (int counter = 0; newCode_imports[counter].dll; counter++)
	{
		(void)memcpy(&newEPdata[i], newCode_imports[counter].dll, strlen(newCode_imports[counter].dll));
		i += ((UINT)strlen(newCode_imports[counter].dll) + 1);

		for (int iD = 0; newCode_imports[counter].calls[iD]; iD++)
		{
			(void)memcpy(&newEPdata[j], newCode_imports[counter].calls[iD], strlen(newCode_imports[counter].calls[iD]));
			j += ((UINT)strlen(newCode_imports[counter].calls[iD]) + 1);
		}

		j += _GAP_FUNCTION_NAMES; //A small gap saparating functions groups
	}
}


//these function will be iserted to host and will only run when host runs it

//here we store all the data we need in order to run the enterd code
int __stdcall NewEntryPoint()
{
	//Find Section Data Address
	DWORD currentAddr = 0;
	DWORD sign = 0;
	DWORD dataSection = 0;
	DWORD dwPwdWindowDS = 0;

	//get current position by jumping to label here and storing it in currentAdd
	__asm {
		call label_EIP
		label_EIP:
		pop currentAddr
	}

	// find <E> flag that points us to end of data section <E> 
	while (sign != 0x3E453C00)
		sign = (DWORD)(*(DWORD *)(--currentAddr));

	//Here we got address of Data Section
	dataSection = currentAddr - (_MAX_SECTION_DATA_SIZE_ - 4);

	//store newEPdata address in PwdWindow data section
	dwPwdWindowDS = *((DWORD *)(dataSection + 12)); //size of new Entry point
	dwPwdWindowDS += (dataSection + _MAX_SECTION_DATA_SIZE_); //newEPcode address = address of newEPdata + size in bytes of newEPdata + size in bytes NewEntryPoint.
	_MEMCPY_((void *)dwPwdWindowDS, &dataSection, sizeof(DWORD));

 
	//get OEP LoadLibray and GetProcAddress we found in fill_data_areas
	WINSTARTFUNC   pfn_OriginalEntryPoint = NULL;
	LOADLIBRARY    pfn_LoadLibrary = NULL;
	GETPROCADDRESS pfn_GetProcAddress = NULL;
	DWORD          dwWrk = 0;

	//get OEP
	pfn_OriginalEntryPoint = (WINSTARTFUNC)(*((DWORD *)dataSection));

	// get LoadLibrary
	dwWrk = *((DWORD *)(dataSection + 4));
	pfn_LoadLibrary = (LOADLIBRARY)(*((DWORD *)(dwWrk)));
	// get GetProcAddress
	dwWrk = *((DWORD *)(dataSection + 8));
	pfn_GetProcAddress = (GETPROCADDRESS)(*((DWORD *)(dwWrk)));

	//get all DLL and Functions we need to run
	char *lpDllName = NULL;
	char *lpAPICall = NULL;
	DWORD dwOffSet0 = dataSection + _OFFSET_DLL_NAMES; //set offset to DLL section in newEPdata
	DWORD dwOffSet1 = dataSection + _OFFSET_FUNCTION_NAMES;//set offset to Function name section in newEPdata
	DWORD dwOffSet2 = dataSection + _OFFSET_FUNCTION_ADDR;//set offset to Function address in newEPdata
	DWORD dwAddr = 0;
	HMODULE hMod = NULL;

	//iterate through all dlls
	while (*(lpDllName = ((char *)dwOffSet0)))
	{
		if ((hMod = pfn_LoadLibrary(lpDllName)) == NULL)
			goto OEP_CALL;
		//iterate through all API functions
		while (*(lpAPICall = ((char *)dwOffSet1)))
		{
			dwAddr = (DWORD)pfn_GetProcAddress(hMod, lpAPICall);//get real address of API function
			(void)_MEMCPY_((void *)dwOffSet2, &dwAddr, sizeof(DWORD));//store its real address in function address section

			dwOffSet2 += sizeof(DWORD);
			dwOffSet1 += ((DWORD)_STRLEN_(lpAPICall) + 1);
		}

		dwOffSet1 += _GAP_FUNCTION_NAMES;
		dwOffSet0 += ((DWORD)_STRLEN_(lpDllName) + 1);
	}

	//get all functions reall address that we found before
	REGISTERCLASSEX   pfn_RegisterClassEx = NULL;
	CREATEWINDOWEX    pfn_CreateWindowEx = NULL;
	SETWINDOWTEXT     pfn_SetWindowText = NULL;
	SHOWWINDOW        pfn_ShowWindow = NULL;
	UPDATEWINDOW      pfn_UpdateWindow = NULL;
	SETFOCUS          pfn_SetFocus = NULL;
	GETMESSAGE        pfn_GetMessage = NULL;
	TRANSLATEMESSAGE  pfn_TranslateMessage = NULL;
	DISPATCHMESSAGE   pfn_DispatchMessage = NULL;
	GETSYSTEMMETRICS  pfn_GetSystemMetrics = NULL;
	EXITPROCESS       pfn_ExitProcess = NULL;
	WINDOWPROCEDURE   pfn_WindowProc = NULL;
	DESTROYWINDOW     pfn_DestroyWindow = NULL;

	dwAddr = dataSection + _OFFSET_FUNCTION_ADDR;

	pfn_RegisterClassEx = (REGISTERCLASSEX)(*((DWORD *)(dwAddr)));
	pfn_CreateWindowEx = (CREATEWINDOWEX)(*((DWORD *)(dwAddr + 4)));
	pfn_SetWindowText = (SETWINDOWTEXT)(*((DWORD *)(dwAddr + 8)));
	pfn_ShowWindow = (SHOWWINDOW)(*((DWORD *)(dwAddr + 12)));
	pfn_UpdateWindow = (UPDATEWINDOW)(*((DWORD *)(dwAddr + 16)));
	pfn_SetFocus = (SETFOCUS)(*((DWORD *)(dwAddr + 20)));
	pfn_GetMessage = (GETMESSAGE)(*((DWORD *)(dwAddr + 24)));
	pfn_TranslateMessage = (TRANSLATEMESSAGE)(*((DWORD *)(dwAddr + 28)));
	pfn_DispatchMessage = (DISPATCHMESSAGE)(*((DWORD *)(dwAddr + 32)));
	pfn_GetSystemMetrics = (GETSYSTEMMETRICS)(*((DWORD *)(dwAddr + 52)));
	pfn_DestroyWindow = (DESTROYWINDOW)(*((DWORD *)(dwAddr + 60)));
	pfn_ExitProcess = (EXITPROCESS)(*((DWORD *)(dwAddr + 64)));


	//we are now set to start our code:
	//here we call all the functions we want to run
	WNDCLASSEX wcex;
	DWORD dwAddrEPStrings = 0;
	HWND  hWnd = NULL;
	HWND  hEdit = NULL;
	MSG   winMsg;

	// get pfn_WindowProc to point to PwdWindow to handle messeges
	dwWrk = (dataSection + _MAX_SECTION_DATA_SIZE_);
	dwWrk += *((DWORD *)(dataSection + 12));
	dwWrk += _MAX_SEC_SECTION_DATA_SIZE_;
	pfn_WindowProc = (WINDOWPROCEDURE)dwWrk;

	//Let's point to program strings
	dwAddrEPStrings = dataSection + _OFFSET_STRINGS;

	// Now lets create the Dialog Window and show it
	(void)_MEMSET_(&wcex, 0x00, sizeof(WNDCLASSEX));
	wcex.cbSize = sizeof(WNDCLASSEX);
	wcex.style = CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc = pfn_WindowProc; //point to procces that will handle messeges sent
	wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW); //white
	wcex.lpszClassName = (char *)(dwAddrEPStrings);
	wcex.cbWndExtra = sizeof(DWORD);

	pfn_RegisterClassEx(&wcex);

	//Main window:
	hWnd = pfn_CreateWindowEx(0,
		(char *)(dwAddrEPStrings), //name of class
		NULL,
		WS_OVERLAPPED,
		pfn_GetSystemMetrics(SM_CXSCREEN) / 2 - 300,
		pfn_GetSystemMetrics(SM_CYSCREEN) / 2 - 300,
		330, 200,
		NULL, NULL, NULL, NULL);

	if (!hWnd)
		return 0;

	//ok botton
	pfn_CreateWindowEx(0,
		(char *)(dwAddrEPStrings + 34), //button
		(char *)(dwAddrEPStrings + 46), //ok
		WS_CHILD | WS_VISIBLE | BS_TEXT,
		200, 60, 100, 30,
		hWnd,
		(HMENU)10123,
		NULL,
		NULL);

	//cancel botton
	pfn_CreateWindowEx(0,
		(char *)(dwAddrEPStrings + 34), //button
		(char *)(dwAddrEPStrings + 49), //cancel
		WS_CHILD | WS_VISIBLE | BS_TEXT,
		200, 100, 100, 30,
		hWnd,
		(HMENU)10456,
		NULL,
		NULL);

	//text box
	hEdit = pfn_CreateWindowEx(0,
		(char *)(dwAddrEPStrings + 41), //edit
		(char *)(dwAddrEPStrings + 88),	//
		WS_CHILD | WS_VISIBLE | WS_BORDER | WS_DISABLED | ES_AUTOHSCROLL,
		10, 10, 170, 90,
		hWnd,
		NULL,
		NULL,
		NULL);

	//password edit
	hEdit = pfn_CreateWindowEx(0,
		(char *)(dwAddrEPStrings + 41), //edit
		NULL,	//
		WS_CHILD | WS_VISIBLE | WS_BORDER | ES_PASSWORD | ES_AUTOHSCROLL,
		10, 105, 170, 25,
		hWnd,
		(HMENU)10789,
		NULL,
		NULL);

	pfn_SetWindowText(hWnd, (char *)(dwAddrEPStrings + 9));
	pfn_ShowWindow(hWnd, SW_SHOW);
	pfn_UpdateWindow(hWnd);

	pfn_SetFocus(hEdit);

	while (pfn_GetMessage(&winMsg, NULL, 0, 0))
	{
		pfn_TranslateMessage(&winMsg);
		pfn_DispatchMessage(&winMsg);
	}

	if ((int)winMsg.wParam == 0)
		pfn_ExitProcess(0); // *** If password is invalid or cancel was clicked

	pfn_DestroyWindow(hWnd);

OEP_CALL:

	pfn_OriginalEntryPoint();

	return 0;
}

//used as marker for size of NewEntryPoint
int __stdcall NewEntryPoint_End()
{
	return 0;
}

LRESULT CALLBACK PwdWindow(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	//Find Section Data Address
	DWORD currentAddr = 0;
	DWORD sign = 0;
	DWORD dataSection = 0;
	DWORD dwSecDataSection = 0;

	//get current position by jumping to label here and storing it in currentAdd
	__asm {
		call lbl_ref1
		lbl_ref1 :
		pop currentAddr
	}

	// find <E> flag that points us to end of data section <E> 
	while (sign != 0x3E453C00)
		sign = (DWORD)(*(DWORD *)(--currentAddr));

	// get address of Secondary Data Section
	dwSecDataSection = currentAddr - (_MAX_SEC_SECTION_DATA_SIZE_ - 4);

	// Here we got address of Data Section
	dataSection = (*((DWORD *)dwSecDataSection));
 
	//map the functions we need from data
	DWORD dwAddr = dataSection + _OFFSET_FUNCTION_ADDR;

	DEFWINDOWPROC     pfn_DefWindowProc = NULL;
	MESSAGEBOX        pfn_MessageBox = NULL;
	POSTQUITMESSAGE   pfn_PostQuitMessage = NULL;
	GETWINDOWTEXT     pfn_GetWindowText = NULL;
	GETDLGITEM        pfn_GetDlgItem = NULL;

	pfn_MessageBox = (MESSAGEBOX)(*((DWORD *)(dwAddr + 40)));
	pfn_PostQuitMessage = (POSTQUITMESSAGE)(*((DWORD *)(dwAddr + 44)));
	pfn_GetWindowText = (GETWINDOWTEXT)(*((DWORD *)(dwAddr + 36)));
	pfn_DefWindowProc = (DEFWINDOWPROC)(*((DWORD *)(dwAddr + 48)));
	pfn_GetDlgItem = (GETDLGITEM)(*((DWORD *)(dwAddr + 56)));


	//program to run when button was clicked
	DWORD dwAddrEPStrings = dataSection + _OFFSET_STRINGS;
	WORD wmId = 0;
	char pwd[64];

	switch (message)
	{
	case WM_COMMAND:
	{
		wmId = LOWORD(wParam);

		switch (wmId)
		{
		case 10123: //ok botton pressed
		{
			_MEMSET_(pwd, 0x00, sizeof(pwd));
			pfn_GetWindowText(pfn_GetDlgItem(hWnd, 10789), pwd, 32);
			if (_STRCMP_(pwd, (char *)(dataSection + 16)))
			{
				pfn_MessageBox(hWnd, (char *)(dwAddrEPStrings + 56), (char *)(dwAddrEPStrings + 77), MB_ICONERROR);
				pfn_PostQuitMessage(0);
			}
			else
				pfn_PostQuitMessage(1);
		}
		break;

		case 10456: //cancel botton pressed
			pfn_PostQuitMessage(0);
			break;

		default:
			break;
		}
	}
	break;

	default:
		return pfn_DefWindowProc(hWnd, message, wParam, lParam);
	}

	return 0;
}

//used as marker for size of PwdWindow
LRESULT __stdcall PwdWindow_End(char *_not_used)
{
	return 0;
}

