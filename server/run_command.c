#include <stdio.h>

#include "run_command.h"
#include "debug.h"
#include "compat.h"

#ifdef WIN32
#include <Windows.h>
#else
//For everybody else...
#define _popen popen  
#define _pclose pclose
#endif

#define CMD_BUFF_DEFAULT_SIZE 128
#define CMD_BUFF_BYTES_TO_READ 126

#ifdef _WINDLL
int run_command(unsigned char* cmd, unsigned char* buf, int* size)
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	HANDLE hChildRead = NULL;
	HANDLE hChildWrite = NULL;
	HANDLE hHiveRead = NULL;
	HANDLE hHiveWrite = NULL;
	HANDLE hRead = NULL;
	HANDLE hWrite = NULL;
	SECURITY_ATTRIBUTES saAttr;
	DWORD dwRead = 0;
	DWORD dwAval = -1;
	DWORD dwLeft = 0;
	DWORD dwExitCode = STILL_ACTIVE;
	BOOL bSuccess = TRUE;
	char temp [CMD_BUFF_DEFAULT_SIZE] = {0};
	unsigned char* ptr = buf;
	int total = 0;


	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	//Create pipes 

	if(!CreatePipe(&hChildRead,&hHiveWrite,NULL,0))
	{
		return -1;
	}

	if(!CreatePipe(&hHiveRead,&hChildWrite,NULL,0))
	{
		return -1;
	}

	DuplicateHandle(GetCurrentProcess(), hChildRead,GetCurrentProcess(),&hRead,0,TRUE, DUPLICATE_SAME_ACCESS);
	DuplicateHandle(GetCurrentProcess(), hChildWrite,GetCurrentProcess(),&hWrite,0,TRUE, DUPLICATE_SAME_ACCESS);

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	si.hStdInput = hRead;
	si.hStdError = hWrite;
	si.hStdOutput = hWrite;
	si.wShowWindow = SW_HIDE;
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	
	ZeroMemory(&pi, sizeof(pi));

	if( !CreateProcess(NULL,(char*)cmd,NULL,NULL,TRUE,0,NULL,NULL,&si,&pi))
	{
		D(printf("CreateProcess failed (%d). \n." GetLastError()));
		return -1;
	}
	
	CloseHandle(hRead);
	CloseHandle(hWrite);
	CloseHandle(hChildRead);
	CloseHandle(hChildWrite);

	//read from pipe in a loop
	while (STILL_ACTIVE == dwExitCode || dwAval != 0) 
	{
		PeekNamedPipe(hHiveRead,temp,CMD_BUFF_BYTES_TO_READ,NULL,&dwAval,NULL);

		GetExitCodeProcess(pi.hProcess,&dwExitCode);

		if(0 < dwAval)
		{
			bSuccess = ReadFile(hHiveRead, temp,CMD_BUFF_BYTES_TO_READ,&dwRead,NULL);

			total += strlen(temp);
			if(total <= *size)
			{
				memcpy(ptr,temp,strlen(temp));
				ptr += strlen(temp);
			}
			memset(temp, 0, CMD_BUFF_DEFAULT_SIZE);
		}	
	}

	CloseHandle(hHiveRead);
	CloseHandle(hHiveWrite);

	if(total > *size)
	{
		*size = total + 1;
		return 1;
	}

	return 0;
}

#else

int run_command(unsigned char* cmd, unsigned char* buf, int* size)
{
	unsigned char* ptr = buf;
	char temp[CMD_BUFF_DEFAULT_SIZE];
	FILE *pPipe;
	int total = 0;
#ifdef WIN32
	char	popen_opts[] = "rt";
#else
	char	popen_opts[] = "r";
#endif

	if( (pPipe = _popen((char *)cmd, popen_opts)) == NULL)
	{
		perror( " popen():" );
		D(printf(" Error!\n");)
		return -1;
	}

#ifndef MIKROTIK
#if defined LINUX || defined SOLARIS
	memcpy( ptr, "\n", 1 );
	ptr += 1;
	total = 1;
#endif	// LINUX || SOLARIS
#endif	// MIKROTIK

// 128 byte buffer - 1 for the terminating NULL - 1 for the prepended \n (Linux & Solaris only) = 126
	while(fgets(temp, CMD_BUFF_BYTES_TO_READ, pPipe))
	{
		total += strlen(temp);
		if(total <= *size)
		{
			memcpy(ptr, temp, strlen(temp));
			ptr += strlen(temp);
		}
		memset(temp, 0, CMD_BUFF_DEFAULT_SIZE);
	}

	_pclose(pPipe);

	if(total > *size)
	{
		*size = total + 1;
		return 1;
	}

	return 0;
}
#endif

// testing
// can be built using:
// gcc run_command.c -DLINUX -D_TEST

#ifdef _TEST
#include <stdlib.h>
int main( void )
{
	char	*buffer = NULL;
	int		size;
	int		rv = 1;	

	// initial buffer size
	size = 2048;

	// run_command returns 1 if buffer is too small for return
	while ( rv == 1 )
	{
//		if ( buffer != NULL ) free( buffer );
//		buffer = malloc( size );
		buffer = realloc( buffer, size );
		memset( buffer, 0, size );
		rv = run_command( "ls -l", buffer, &size );
	}

	
	printf( "\n *** Return is size %d bytes *** \n\n", size );

	printf( "%s\n", buffer );

	if ( buffer != NULL ) free( buffer );

	return 0;
}
#endif
