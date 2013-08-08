#ifdef WIN32
#include <Windows.h>
#else
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#endif

#include <stdio.h>
#include "get_data.h"
#include "proj_strings.h"
#include "debug.h"
#include "run_command.h"

unsigned char* get_data(int* size, int flag)
{
	int retVal = 0;
	unsigned char* buf = NULL;
	unsigned char* cmd_str = NULL;
#ifdef WIN32
	DWORD dwVersion = 0; 
	DWORD dwMajorVersion = 0;
	DWORD dwMinorVersion = 0; 
	DWORD dwBuild = 0;
#endif



	buf = (unsigned char*) malloc(*size);
	memset(buf,0,*size);

#ifdef WIN32
	if(flag == GD_PROC_LIST)
	{
		free(buf);
		buf = (unsigned char*) malloc(14);
		dwVersion = GetVersion();
	
		// Get the Windows version.
	
		dwMajorVersion = (DWORD)(LOBYTE(LOWORD(dwVersion)));
		dwMinorVersion = (DWORD)(HIBYTE(LOWORD(dwVersion)));
	
		// Get the build number.
	
		if (dwVersion < 0x80000000)              
			dwBuild = (DWORD)(HIWORD(dwVersion));
	
		if((dwMajorVersion == 5) && (dwMinorVersion == 0))
		{
			//#define n w2nsupst "Not supported"
			sprintf((char*)buf,w2nsupst);
			*size = 14;//strlen((char*)buf)+1;
			return buf;
		}
	}

#endif

	switch (flag)
	{
	case GD_PROC_LIST:
#ifdef WIN32
		cmd_str = bws1;
#else
		cmd_str = bus1;
#endif
		break;
	case GD_IPCONFIG:
#ifdef WIN32
		cmd_str = bws2;
#else
		cmd_str = bus2;
#endif
		break;
	case GD_NETSTAT_AN:
#ifdef WIN32
		cmd_str = win_netstat_an;
#elif SOLARIS
		cmd_str = bb22;
#else
		cmd_str = bb2;
#endif
		break;
	case GD_NETSTAT_RN:
		cmd_str = bb1;
		break;
	}

	retVal = run_command(cmd_str,buf,size);
	if(retVal == 1)
	{
		free(buf);
		buf = (unsigned char*) malloc(*size);
		memset(buf,0,*size);
		retVal = run_command(cmd_str,buf,size);
		if(retVal == -1 || retVal == 1)
		{
			D(printf("Could not get process list!\n"));
			free(buf);
			return NULL;
		}
	}
	else if( retVal == -1)
	{
		D(printf("Could not get process list!\n"));
		free(buf);
		return NULL;
	}

	return buf;
}
