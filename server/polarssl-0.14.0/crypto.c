#ifdef __cplusplus
extern "C" {
#endif

#include "crypto.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// debug.h will get included from the client and/or server specific directories.
#include "../debug.h"

//*******************************************************
#define DEBUG_LEVEL 0

//*******************************************************
void my_debug( void *ctx, int level, const char *str )
{
    if( level < DEBUG_LEVEL )
    {
        fprintf( (FILE *) ctx, "%s", str );
        fflush(  (FILE *) ctx  );
    }
}

//*******************************************************
int crypt_handshake( ssl_context *ssl )
{
	int ret;
    /*
     * 5. Handshake
     */
    D( printf( "  . Performing the TLS handshake.........." ); )

    while( ( ret = ssl_handshake( ssl ) ) != 0 )
    {
        if( ret != POLARSSL_ERR_NET_TRY_AGAIN )
        {
            D( printf( " failed\n" ); )
			D( printf( " ERROR: ! ssl_handshake returned %d\n", ret ); )
			return -1;
        }
    }

    D( printf( " ok\n" ); )

	return 0;
}

//*******************************************************
int crypt_write( ssl_context *ssl, unsigned char *buf, int size )
{
	int		ret;

	D( printf( " DEBUG: crypt_write():" ); )

    while( ( ret = ssl_write( ssl, buf, size ) ) <= 0 )
    {
        if( ret != POLARSSL_ERR_NET_TRY_AGAIN )
        {
            D( printf( " failed  ! ssl_write returned %d\n", ret ); )
			return ret;
        }
    }

	D( printf( " %d bytes written\n", ret ); )
	return ret;

}

//*******************************************************
int crypt_read( ssl_context *ssl, unsigned char *buf, int bufsize )
{
	int		ret;

	// TODO: look at this do/while loop again.  it only runs once.
	// does it serve any other purpose?
    do
    {
        memset( buf, 0, bufsize );

        ret = ssl_read( ssl, buf, bufsize );

        if( ret == POLARSSL_ERR_NET_TRY_AGAIN )
		{
			D( printf( " DEBUG: crypt_read(): POLARSSL_ERR_NET_TRY_AGAIN\n" ); )
            continue;
		}

        if( ret == POLARSSL_ERR_SSL_PEER_CLOSE_NOTIFY )
		{
			D( printf( " DEBUG: crypt_read(): POLARSSL_ERR_SSL_PEER_CLOSE_NOTIFY\n" ); )
            break;
		}

        if( ret <= 0 )
        {
            D( printf( " ! ERROR: crypt_read() failed. ssl_read returned %d\n", ret ); )
            break;
        }

        D( printf( " . DEBUG: crypt_read(): %d bytes read\n", ret ); )
    }
    while( 0 );

	return ret;
}

//*******************************************************
int crypt_close_notify( ssl_context *ssl)
{
    return ssl_close_notify( ssl );
}

//*******************************************************
int crypt_setup_client( havege_state *hs, ssl_context *ssl, ssl_session *ssn, int *sockfd )
{
	int		ret;

    /*
     * 0. Initialize the RNG and the session data
     */
    havege_init( hs );
    memset( ssn, 0, sizeof( ssl_session ) );

    /*
     * 2. Setup stuff
     */
    D( printf( "  . Initializing the TLS structure........" ); )

    if( ( ret = ssl_init( ssl ) ) != 0 )
    {
        D( printf( " failed\n" ); )
		D( printf( " ERROR: ! ssl_init returned %d\n", ret ); )
		return -1;
    }
    D( printf( " ok\n" ); )

    ssl_set_endpoint( ssl, SSL_IS_CLIENT );
    ssl_set_authmode( ssl, SSL_VERIFY_NONE );

    ssl_set_rng( ssl, havege_rand, hs );
    ssl_set_dbg( ssl, my_debug, stdout );
    ssl_set_bio( ssl, net_recv, sockfd, net_send, sockfd );

    ssl_set_ciphers( ssl, ssl_default_ciphers );
    ssl_set_session( ssl, 1, 600, ssn );

	return 0;
}


//*******************************************************
int crypt_cleanup( ssl_context *ssl )
{
    ssl_free( ssl );

    memset( ssl, 0, sizeof( ssl_context ) );

	return 0;
}

#ifdef __cplusplus
}
#endif

