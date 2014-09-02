#include "hclient.h"
#include "debug.h"
#include "threads.h"
#include "crypto.h"
#include "colors.h"

#include "proj_strings.h"     //Required for strings...

#include "../common/crypto/dhExchange.c"  //Required for dh Key information

#include <pthread.h>

//**************************************************************
pthread_mutex_t		tlock;

//**************************************************************
void Run( struct proc_vars* info, struct trigger_params *trigger_args )
{
	ctr_drbg_context 	ctr_drbg;
	ssl_context		ssl;
	ssl_session		ssn;
	int 			sKeyRet;
 
	pthread_mutex_init( &tlock, NULL );

	// if we aren't listening, then we don't need to take the lock.
	// taking the lock allows us to set-up the listening socket before sending the trigger packet(s)
	if ( info->listen == YES )
	{
		DLX(2, printf( " Requesting pthread_mutex_lock \n"));
		pthread_mutex_lock( &tlock );
		DLX(2, printf( " pthread_mutex_lock locked\n"));
	}

	// to avoid race condition where main thread exits before trigger is set,
	// don't call tigger_start() as a thread
	if ( info->trigger == YES && info->listen == NO )
	{
		DLX(2, printf( " Trigger mode set\n"));
		trigger_start ( (void *) trigger_args );
		return;
	}

	if ( info->trigger == YES && info->listen == YES )
	{
		DLX(2, printf( " Trigger mode set\n"));
		make_thread( trigger_start, (void *) trigger_args );
	}

	if ( info->listen == NO )
	{
		// trigger sent, if specified.  if not configured to listen, we are done.
		// not reached
		return;
	}

	DLX(2, printf( " Listen mode set\n"));
	// listen for and establish TCP connection. returns with accept() returns success
	if ( TcpInit( info ) == ERROR )
	{
		DLX(2, printf( " ERROR: TcpInit() returned error.\n"));
		return;
	}

	// at this point, we have an establish TCP/IP connection
	DisplayStatus(info);

	//printf( "\n %sEnabling encrypted communications:%s\n", BLUE, RESET );
	printf( "\n %s%s:%s\n", BLUE, run1String, RESET );

	// from a SSL/TLS perspective, the client acts like a SSL server
	if ( crypt_setup_server( &ctr_drbg, &ssl, &ssn, &(info->tcpfd) ) != SUCCESS )
	{
		DLX(2, printf( " ERROR: crypt_setup_server() failed\n"));
		return;
	}
	DL(2);
	// start TLS handshake
	if ( crypt_handshake( &ssl ) != SUCCESS )
	{
		// TODO: encode this string(s)
		//printf( " ERROR: TLS connection with TLS client failed to initialize.\n" ); 
		printf( "%s", run2String ); 
		return;
	}
	DLX(2, printf( " TLS handshake complete.\n"));
	printf( "\n" );

    //Check Diffie Hellman Key...
    //See if Secret Key is available
	sKeyRet=find_DH_SecretKey(&ssl);
	if (sKeyRet == 0)
	{
		DLX(4, printf( "DH_Secret Key is not null\n"));
	}
	else
	{
		DLX(4, printf( "DH Secret Key K not	found and returned %d.\n",sKeyRet));
	}

	// The following if statement used to have an else clause to call AutomaticMode() which did nothing.
	if ( info->interactive == YES )
	{
		InteractiveMode( info, &ssl );
	}

	crypt_close_notify( &ssl );

	return;
}

//**************************************************************
void InteractiveMode( struct proc_vars* info, ssl_context *ssl )
{
   char cline[525];
   char** argv;


   while ((info->command != EXIT) && (info->command != SHUTDOWNBOTH)) {
      memset(cline, 0, 525);
      fprintf(stdout, "%s> ", info->progname);
      (void) fgets(cline, 525, stdin);
      cline[strlen(cline) - 1] = '\0';
      argv = BuildArgv(cline);
      if ((argv != NULL) && (argv[0] != '\0')) {
         CommandToFunction(argv, info, ssl );
      }
      FreeArgv(argv);
   }

}
