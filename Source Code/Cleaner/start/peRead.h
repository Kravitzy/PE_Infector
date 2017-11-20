#pragma once

class PE {
public:
	PE();
	~PE();
	DWORD align(DWORD size, DWORD align, DWORD addr);
	bool RemoveSection(char * filepath);
	bool ChangeOEP(char * filepath, const char* password);

};