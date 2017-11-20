#include <stdio.h>
#include <windows.h>
#include <string>
#include <iostream>
#include "peRead.h"
#include "Source.h"

using namespace std;

int main(int argc, char** argv) {

	PE m_pe;

	bool check_pass = m_pe.ChangeOEP(argv[1], (const char *)argv[2]);
	if (check_pass) {
		m_pe.RemoveSection(argv[1]);
	}


	return 0;
}