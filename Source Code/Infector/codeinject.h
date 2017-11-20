#pragma once
#include "stdafx.h"
#include <stdio.h>
#include <windows.h>
#include <stdlib.h>
#include "PETool.h"


//structure of new program we are going to insert:
#define _OFFSET_STRINGS         32
#define _OFFSET_DLL_NAMES       200
#define _OFFSET_FUNCTION_NAMES  250
#define _OFFSET_FUNCTION_ADDR   600
#define _MAX_SECTION_DATA_SIZE_ 1024
#define _MAX_SECTION_SIZE       4096
#define _GAP_FUNCTION_NAMES     5
#define _MAX_SEC_SECTION_DATA_SIZE_ 16

// *** New Section
extern BYTE newEPsection[_MAX_SECTION_SIZE];
// *** Memory used by NewEntryPoint
extern BYTE newEPdata[_MAX_SECTION_DATA_SIZE_];
// *** Used by PwdWindow to link to vg_data_ep_data
extern BYTE newEPcode[_MAX_SEC_SECTION_DATA_SIZE_];

//define API functions we need to run new code
typedef FARPROC(WINAPI *GETPROCADDRESS)(HMODULE, LPCSTR);
typedef HMODULE(WINAPI *LOADLIBRARY)(LPCSTR);
typedef ATOM(WINAPI *REGISTERCLASSEX)(CONST WNDCLASSEXA *);
typedef HWND(WINAPI *CREATEWINDOWEX)(__in DWORD dwExStyle, __in_opt LPCSTR lpClassName, __in_opt LPCSTR lpWindowName, __in DWORD dwStyle, __in int X, __in int Y, __in int nWidth, __in int nHeight, __in_opt HWND hWndParent, __in_opt HMENU hMenu, __in_opt HINSTANCE hInstance, __in_opt LPVOID lpParam);
typedef BOOL(WINAPI *SETWINDOWTEXT)(__in HWND hWnd, __in_opt LPCSTR lpString);
typedef BOOL(WINAPI *SHOWWINDOW)(__in HWND hWnd, __in int nCmdShow);
typedef BOOL(WINAPI *UPDATEWINDOW)(__in HWND hWnd);
typedef HWND(WINAPI *SETFOCUS)(__in_opt HWND hWnd);
typedef BOOL(WINAPI *GETMESSAGE)(__out LPMSG lpMsg, __in_opt HWND hWnd, __in UINT wMsgFilterMin, __in UINT wMsgFilterMax);
typedef BOOL(WINAPI *TRANSLATEMESSAGE)(__in CONST MSG *lpMsg);
typedef LRESULT(WINAPI *DISPATCHMESSAGE)(__in CONST MSG *lpMsg);
typedef int (WINAPI *GETWINDOWTEXT)(__in HWND hWnd, __out_ecount(nMaxCount) LPSTR lpString, __in int nMaxCount);
typedef int (WINAPI *MESSAGEBOX)(__in_opt HWND hWnd, __in_opt LPCSTR lpText, __in_opt LPCSTR lpCaption, __in UINT uType);
typedef VOID(WINAPI *POSTQUITMESSAGE)(__in int nExitCode);
typedef LRESULT(WINAPI *DEFWINDOWPROC)(__in HWND hWnd, __in UINT Msg, __in WPARAM wParam, __in LPARAM lParam);
typedef int (WINAPI *GETSYSTEMMETRICS)(__in int nIndex);
typedef HWND(WINAPI *GETDLGITEM)(__in_opt HWND hDlg, __in int nIDDlgItem);
typedef VOID(WINAPI *EXITPROCESS)(__in UINT uExitCode);
typedef BOOL(WINAPI *DESTROYWINDOW)(__in HWND hWnd);
typedef void(_stdcall *WINSTARTFUNC)(void);
typedef LRESULT(CALLBACK *WINDOWPROCEDURE)(HWND, UINT, WPARAM, LPARAM);

typedef struct API_FUNCTIONS
{
   char *dll;
   char *calls[64];
} API_FUNCTIONS;
//api functions we need to import for our new code to run
API_FUNCTIONS newCode_imports[] = {
   { "USER32.DLL", 
      {
         "RegisterClassExA",  // 00  / ref offset = 0 
         "CreateWindowExA",   // 17  / ref offset = 4
         "SetWindowTextA",    // 33  / ref offset = 8
         "ShowWindow",        // 48  / ref offset = 12
         "UpdateWindow",      // 59  / ref offset = 16
         "SetFocus",          // 72  / ref offset = 20
         "GetMessageA",       // 81  / ref offset = 24
         "TranslateMessage",  // 93  / ref offset = 28
         "DispatchMessageA",  // 110 / ref offset = 32 
         "GetWindowTextA",    // 127 / ref offset = 36
         "MessageBoxA",       // 142 / ref offset = 40
         "PostQuitMessage",   // 154 / ref offset = 44
         "DefWindowProcA",    // 170 / ref offset = 48
         "GetSystemMetrics",  // 185 / ref offset = 52
         "GetDlgItem",        // 202 / ref offset = 56 
         "DestroyWindow",     // 212 / ref offset = 60
         NULL 
      }
   }, // USER32.DLL

   { "KERNEL32.DLL", 
      {
         "ExitProcess",       // 230 ( 225 + _GAP_FUNCTION_NAMES )  / ref offset = 64
         NULL 
      }
   }, // KERNEL32.DLL

   { NULL, { NULL } }
};
char* newCode_strings[] = {
	"licence.",                // offset = 0 bytes 
	"Please purchase software",  // offset = 9 bytes 
	"BUTTON",                  // offset = 35 bytes 
	"EDIT",                    // offset = 41 bytes 
	"OK",                      // offset = 46 bytes 
	"Cancel",                  // offset = 49 bytes 
	"Sorry! Wrong password.",  // offset = 56 bytes 
	"Password",                // offset = 79 bytes (not used in codeinject.exe)
	"Insert Password", // offset = 88
NULL };

void fill_data_areas(PETool *pe, char *password);

//create new code function 
int __stdcall NewEntryPoint();
int __stdcall NewEntryPoint_End(); //we use this in order to find size of new code

//dialuge part of new code
LRESULT CALLBACK  PwdWindow(HWND, UINT, WPARAM, LPARAM);
LRESULT __stdcall PwdWindow_End(char *_not_used);//use this to size of dialoge part of code



// costum made function in order to force inline functions
// Important: Compiler must set /O2 (Maximize Speed) to ensure inline functions

__forceinline void _MEMSET_(void *_dst, int _val, size_t _sz)
{
	while (_sz) ((BYTE *)_dst)[--_sz] = _val;
}

__forceinline void _MEMCPY_(void *_dst, void *_src, size_t _sz)
{
	while (_sz--) ((BYTE *)_dst)[_sz] = ((BYTE *)_src)[_sz];
}

__forceinline BOOL _MEMCMP_(void *_src1, void *_src2, size_t _sz)
{
	while (_sz--)
	{
		if (((BYTE *)_src1)[_sz] != ((BYTE *)_src2)[_sz])
			return FALSE;
	}

	return TRUE;
}

__forceinline size_t _STRLEN_(char *_src)
{
	size_t count = 0;
	while (_src && *_src++) count++;
	return count;
}

__forceinline int _STRCMP_(char *_src1, char *_src2)
{
	size_t sz = _STRLEN_(_src1);

	if (_STRLEN_(_src1) != _STRLEN_(_src2))
		return 1;

	return _MEMCMP_(_src1, _src2, sz) ? 0 : 1;
}




