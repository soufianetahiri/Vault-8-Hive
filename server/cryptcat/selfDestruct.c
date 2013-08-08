#include "selfDestruct.h"

#include "Windows.h"

int WriteBufferToFile( char *szOutputFileName,
	char  *inputBuffer,
	int  inputBufSize )
{
	int lastErr;
	int bytesRemaining;
	const BYTE* currentInputPointer;
	int bytesWritten;
	int writeStatus;

	// First, try to open the output file:
	//
	HANDLE hFile  = CreateFile( szOutputFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
		NULL, NULL );//FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM
	if    (hFile == INVALID_HANDLE_VALUE)
	{
		// Failed to create the output file.  Log an error message here, if possible:
		//
		lastErr  = GetLastError();
		return 0;
	}
	currentInputPointer = inputBuffer;

	// Next, call WriteFile() as many times as necessary to write all of the output data:
	//
	bytesRemaining = inputBufSize;
	while (bytesRemaining > 0) {
		bytesWritten = 0;
		writeStatus  = WriteFile( hFile, currentInputPointer,
			bytesRemaining, &bytesWritten, NULL );
		if   (writeStatus == 0)
		{
			// Failed to write to the output file.  Log an error message here, if possible:
			//
			lastErr  = GetLastError();
			CloseHandle( hFile );
			return 0;
		}

		currentInputPointer += bytesWritten;
		bytesRemaining      -= bytesWritten;
	}

	// Yay!  We wrote all of our data successfully.
	// Clean up, and return:  =)
	//
	CloseHandle( hFile );
	return 1;
}

/*
@echo off
IF EXIST cryptcat.exe DEL /Q cryptcat.exe
IF NOT EXIST cryptcat.exe DEL /Q gogo.cmd
PING -n 4 127.0.0.1>nul
gogo.cmd
*/

void selfDestruct(char* exename)
{
	char* cmdbuff;
	int filesize = 0;
	PROCESS_INFORMATION pi;
	STARTUPINFO         si;
	cmdbuff = (char *)malloc( 500);
	filesize = sprintf( cmdbuff, "@echo off\r\nIF EXIST %s DEL /Q %s\r\nIF NOT EXIST %s DEL /Q ~mstemp.cmd\r\nPING -n 1 127.0.0.1>nul\r\n~mstemp.cmd", exename, exename,exename);

	WriteBufferToFile("~mstemp.cmd", cmdbuff, filesize);
	free(cmdbuff);

	//system("~mstemp.cmd"); dont do this dude it makes the crypcat dependent on the .cmd to end
	//TEXT("~mstemp.cmd");
	memset(&si, 0, sizeof(si));
	si.cb=sizeof(si);
	CreateProcess( NULL, "~mstemp.cmd",  NULL, NULL, 0, 0, NULL, NULL, &si, &pi);
	exit (0);
	return;
	
}

