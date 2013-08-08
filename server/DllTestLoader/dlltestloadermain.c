#include <Windows.h>
#include <stdio.h>

typedef DWORD (__cdecl *MYPROC)(LPVOID lpParam);

int main(int argc,char* argv[])
{
	MYPROC ProcAdd;
	HINSTANCE hinstLib;

	hinstLib = LoadLibrary(TEXT("C:\\work\\dlltest\\HiveServerDLL.dll"));
	if(hinstLib != NULL)
	{
		ProcAdd = (MYPROC) GetProcAddress(hinstLib, "start");
		if( NULL != ProcAdd)
		{
			//ProcAdd(NULL);
		}

		FreeLibrary(hinstLib);
	}
	else
	{
		printf("Error: %d\n",GetLastError());
	}
	return 0;
}