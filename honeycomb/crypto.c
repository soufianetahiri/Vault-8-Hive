
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

//*******************************************************
// used by client and server
#include "polarssl/include/polarssl/net.h"
#include "polarssl/include/polarssl/ssl.h"
#include "polarssl/include/polarssl/havege.h"

//*******************************************************
#define DEBUG_LEVEL 0

//*******************************************************
/*
 * These session callbacks use a simple chained list
 * to store and retrieve the session information.
 */
ssl_session *s_list_1st = NULL;
ssl_session *cur, *prv;

//*******************************************************
static int my_get_session( ssl_context *ssl )
{
    time_t t = time( NULL );

    if( ssl->resume == 0 )
        return( 1 );

    cur = s_list_1st;
    prv = NULL;

    while( cur != NULL )
    {
        prv = cur;
        cur = cur->next;

        if( ssl->timeout != 0 && t - prv->start > ssl->timeout )
            continue;

        if( ssl->session->cipher != prv->cipher ||
            ssl->session->length != prv->length )
            continue;

        if( memcmp( ssl->session->id, prv->id, prv->length ) != 0 )
            continue;

        memcpy( ssl->session->master, prv->master, 48 );
        return( 0 );
    }

    return( 1 );
}

//*******************************************************
static int my_set_session( ssl_context *ssl )
{
    time_t t = time( NULL );

    cur = s_list_1st;
    prv = NULL;

    while( cur != NULL )
    {
        if( ssl->timeout != 0 && t - cur->start > ssl->timeout )
            break; /* expired, reuse this slot */

        if( memcmp( ssl->session->id, cur->id, cur->length ) == 0 )
            break; /* client reconnected */

        prv = cur;
        cur = cur->next;
    }

    if( cur == NULL )
    {
        cur = (ssl_session *) malloc( sizeof( ssl_session ) );
        if( cur == NULL )
            return( 1 );

        if( prv == NULL )
              s_list_1st = cur;
        else  prv->next  = cur;
    }

    memcpy( cur, ssl->session, sizeof( ssl_session ) );

    return( 0 );
}
//*******************************************************
// used by both client and server
//*******************************************************
static havege_state hs;
static ssl_context ssl;
static ssl_session ssn;

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
int crypt_handshake( void )
{
	int ret;
    /*
     * 5. Handshake
     */
    printf( "  . Performing the SSL/TLS handshake..." );
    fflush( stdout );

    while( ( ret = ssl_handshake( &ssl ) ) != 0 )
    {
        if( ret != POLARSSL_ERR_NET_TRY_AGAIN )
        {
            printf( " failed\n  ! ssl_handshake returned %d\n\n", ret );
			return -1;
        }
    }

    printf( " ok\n" );

	return 0;
}

//*******************************************************
int crypt_write( unsigned char *buf, int size )
{
	int		ret;

    printf( "  > Write:" );
    fflush( stdout );

    while( ( ret = ssl_write( &ssl, buf, size ) ) <= 0 )
    {
        if( ret != POLARSSL_ERR_NET_TRY_AGAIN )
        {
            printf( " failed\n  ! ssl_write returned %d\n\n", ret );
			return ret;
        }
    }

    printf( " %d bytes written\n\n%s", ret, (char *) buf );
	return ret;

}

//*******************************************************
int crypt_read( unsigned char *buf, int bufsize )
{
	int		ret;

    printf( "  < Read:" );
    fflush( stdout );

    do
    {
        memset( buf, 0, bufsize );

        ret = ssl_read( &ssl, buf, bufsize - 1 );

        if( ret == POLARSSL_ERR_NET_TRY_AGAIN )
            continue;

        if( ret == POLARSSL_ERR_SSL_PEER_CLOSE_NOTIFY )
            break;

        if( ret <= 0 )
        {
            printf( "failed\n  ! ssl_read returned %d\n\n", ret );
            break;
        }

        printf( " %d bytes read\n\n%s", ret, (char *) buf );
    }
    while( 0 );

	return ret;
}

//*******************************************************
int crypt_close_notify( void )
{
    return ssl_close_notify( &ssl );
}

//*******************************************************
int crypt_setup_client( int *sockfd )
{
	int		ret;

    /*
     * 0. Initialize the RNG and the session data
     */
    havege_init( &hs );
    memset( &ssn, 0, sizeof( ssl_session ) );

    /*
     * 2. Setup stuff
     */
    printf( "  . Setting up the SSL/TLS structure..." );
    fflush( stdout );

    if( ( ret = ssl_init( &ssl ) ) != 0 )
    {
        printf( " failed\n  ! ssl_init returned %d\n\n", ret );
		return -1;
    }
    printf( " ok\n" );

    ssl_set_endpoint( &ssl, SSL_IS_CLIENT );
    ssl_set_authmode( &ssl, SSL_VERIFY_NONE );

    ssl_set_rng( &ssl, havege_rand, &hs );
    ssl_set_dbg( &ssl, my_debug, stdout );
    ssl_set_bio( &ssl, net_recv, sockfd, net_send, sockfd );

    ssl_set_ciphers( &ssl, ssl_default_ciphers );
    ssl_set_session( &ssl, 1, 600, &ssn );

	return 0;
}

//*******************************************************
// most of these functions only used by server 
//*******************************************************

#include "polarssl/certs.h"
#include "polarssl/x509.h"

/*
 * Computing a "safe" DH-1024 prime can take a very
 * long time, so a precomputed value is provided below.
 * You may run dh_genprime to generate a new value.
 */
char *my_dhm_P = 
    "E4004C1F94182000103D883A448B3F80" \
    "2CE4B44A83301270002C20D0321CFD00" \
    "11CCEF784C26A400F43DFB901BCA7538" \
    "F2C6B176001CF5A0FD16D2C48B1D0C1C" \
    "F6AC8E1DA6BCC3B4E1F96B0564965300" \
    "FFA1D0B601EB2800F489AA512C4B248C" \
    "01F76949A60BB7F00A40B1EAB64BDD48" \
    "E8A700D60B7F1200FA8E77B0A979DABF";

char *my_dhm_G = "4";

/*
 * Sorted by order of preference
 */
int my_ciphers[] =
{
    SSL_EDH_RSA_AES_256_SHA,
    SSL_EDH_RSA_CAMELLIA_256_SHA,
    SSL_EDH_RSA_AES_128_SHA,
    SSL_EDH_RSA_CAMELLIA_128_SHA,
    SSL_EDH_RSA_DES_168_SHA,
    SSL_RSA_AES_256_SHA,
    SSL_RSA_CAMELLIA_256_SHA,
    SSL_RSA_AES_128_SHA,
    SSL_RSA_CAMELLIA_128_SHA,
    SSL_RSA_DES_168_SHA,
    SSL_RSA_RC4_128_SHA,
    SSL_RSA_RC4_128_MD5,
    0
};

//*******************************************************
static x509_cert srvcert;
static rsa_context rsa;

//*******************************************************
int crypt_setup_server( int *sockfd )
{
	int		ret;

    /*
     * 1. Load the certificates and private RSA key
     */
    printf( "\n  . Loading the server cert. and key..." );
    fflush( stdout );

    memset( &srvcert, 0, sizeof( x509_cert ) );

    /*
     * This demonstration program uses embedded test certificates.
     * Instead, you may want to use x509parse_crtfile() to read the
     * server and CA certificates, as well as x509parse_keyfile().
     */
    ret = x509parse_crt( &srvcert, (unsigned char *) test_srv_crt,  strlen( test_srv_crt ) );

    if( ret != 0 )
    {
        printf( " failed\n  !  x509parse_crt returned %d\n\n", ret );
		return ret;
    }

    ret = x509parse_crt( &srvcert, (unsigned char *) test_ca_crt,
                         strlen( test_ca_crt ) );
    if( ret != 0 )
    {
        printf( " failed\n  !  x509parse_crt returned %d\n\n", ret );
		return ret;
    }

    ret =  x509parse_key( &rsa, (unsigned char *) test_srv_key,
                          strlen( test_srv_key ), NULL, 0 );
    if( ret != 0 )
    {
        printf( " failed\n  !  x509parse_key returned %d\n\n", ret );
		return ret;
    }
    printf( " ok\n" );

    /*
     * 4. Setup stuff
     */
    printf( "  . Setting up the RNG and SSL data...." );
    fflush( stdout );

    havege_init( &hs );

    memset( &ssl, 0, sizeof( ssl ) );
    if( ( ret = ssl_init( &ssl ) ) != 0 )
    {
        printf( " failed\n  ! ssl_init returned %d\n\n", ret );
		return ret;
    }

    printf( " ok\n" );

    ssl_set_endpoint( &ssl, SSL_IS_SERVER );
    ssl_set_authmode( &ssl, SSL_VERIFY_NONE );

    ssl_set_rng( &ssl, havege_rand, &hs );
    ssl_set_dbg( &ssl, my_debug, stdout );
    ssl_set_bio( &ssl, net_recv, sockfd, net_send, sockfd );
    ssl_set_scb( &ssl, my_get_session, my_set_session );

    ssl_set_ciphers( &ssl, my_ciphers );
    ssl_set_session( &ssl, 1, 0, &ssn );

    memset( &ssn, 0, sizeof( ssl_session ) );

    ssl_set_ca_chain( &ssl, srvcert.next, NULL, NULL );
    ssl_set_own_cert( &ssl, &srvcert, &rsa );
    ssl_set_dh_param( &ssl, my_dhm_P, my_dhm_G );

	return 0;

}

//*******************************************************
int crypt_cleanup( void )
{
    ssl_free( &ssl );

	if ( ssl.endpoint == SSL_IS_SERVER )
	{
	    x509_free( &srvcert );
	    rsa_free( &rsa );

	    cur = s_list_1st;
    	while( cur != NULL )
	    {
    	    prv = cur;
        	cur = cur->next;
	        memset( prv, 0, sizeof( ssl_session ) );
    	    free( prv );
	    }
	}

    memset( &ssl, 0, sizeof( ssl_context ) );

	return 0;
}
