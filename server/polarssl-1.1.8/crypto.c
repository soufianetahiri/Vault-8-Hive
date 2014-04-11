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
    DLX(4, printf("\tPerforming the TLS handshake... "));

    while( ( ret = ssl_handshake( ssl ) ) != 0 )
    {
        if (ret != POLARSSL_ERR_NET_WANT_WRITE || ret != POLARSSL_ERR_NET_WANT_READ)
        {
            DLX(4, printf("failed, returned: %0x\n", ret));
            return -1;
        }
    }

    DLX(4, printf("ok\n"));

	return 0;
}

//*******************************************************
int crypt_write( ssl_context *ssl, unsigned char *buf, int size )
{
	int	ret = 0;
	int	sent = 0;

	DL(4);
	do {
		ret = ssl_write( ssl, buf, size );
		if (ret == POLARSSL_ERR_NET_WANT_WRITE) {
			DLX(4, printf("POLARSSL_ERR_NET_WANT_WRITE\n"));
			continue;
		}
		else if (ret < 0) {
			DLX(4, printf("failed: ret = %0x\n", ret));
			return ret;
		}
		size -= ret;
		sent += ret;
	} while (size);
	return (sent);
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

        if (ret == POLARSSL_ERR_NET_WANT_READ)
		{
			DLX(4, printf("POLARSSL_ERR_NET_WANT_READ\n"));
            continue;
		}

        if( ret == POLARSSL_ERR_SSL_PEER_CLOSE_NOTIFY )
		{
			DLX(4, printf("POLARSSL_ERR_SSL_PEER_CLOSE_NOTIFY\n"));
            break;
		}

        if( ret <= 0 )
        {
            DLX(4, printf("ERROR: crypt_read() failed. ssl_read returned %0x\n", ret));
            break;
        }

        DLX(4, printf("crypt_read(): %d bytes read\n", ret ));
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
    DLX(4, printf( "\tInitializing the TLS structure..."));

    if( ( ret = ssl_init( ssl ) ) != 0 )
    {
        DLX(4, printf( " failed, ssl_init returned: %d\n", ret));
	return -1;
    }
    DLX(4, printf( " ok\n"));

    ssl_set_endpoint( ssl, SSL_IS_CLIENT );
    ssl_set_authmode( ssl, SSL_VERIFY_NONE );

    ssl_set_rng( ssl, havege_random, hs );
    ssl_set_dbg( ssl, my_debug, stdout );
    ssl_set_bio( ssl, net_recv, sockfd, net_send, sockfd );

    ssl_set_ciphersuites( ssl, ssl_default_ciphersuites );
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

