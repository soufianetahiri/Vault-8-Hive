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
#define DEBUG_LEVEL	0
#define FAILURE		-1

#ifdef SSL_SERVER

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
#endif
//*******************************************************
// used by both client and server
//*******************************************************
//static havege_state hs;
//static ssl_context ssl;
//static ssl_session ssn;

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

#ifdef SSL_SERVER
//*******************************************************
// most of these functions only used by server 
//*******************************************************

#include "polarssl/x509.h"

/*
 * Computing a "safe" DH-1024 prime can take a very
 * long time, so a precomputed value is provided similar to that below
 * and is placed in the file crypto_strings.txt. The prime number and
 * generator is computed using the following openssl command:
 * 	openssl dhparam -[ 2 | 5 ] -text 1024
 * The resulting prime is stripped of its ":"s
 */
/*char *my_dhm_P = 
	"9AF82179E27FBCE16709BB95796C5D12" \
	"357BC034D507CF09F64085D2FA475386" \
	"8298642DC4A8228387615AA8DFDFB4BB" \
	"4C20232E3D6AACEE22D71E8A2BADCB06" \
	"1E39CA06281048EC875FEEC82AB86BB8" \
	"30748EE3372416792AAFA9291FF6654A" \
	"849C3F0DA5BA31F000EF6E706F4314C9" \
	"646DBF7B87D14522501E6EEE905CB447";
*/

char *my_dhm_P= (char *) my_dhm_P_String;

//char *my_dhm_G = "4";
char *my_dhm_G= (char *) my_dhm_G_String;

/*
 * Sorted by order of preference
 */
#if 0
// = ssl_default_ciphers;
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
#endif 



//*******************************************************
static x509_cert srvcert, ca_chain;
static rsa_context rsa;

//*******************************************************
int crypt_setup_server( havege_state *hs, ssl_context *ssl, ssl_session *ssn, int *sockfd )
{
	int ret;
	int certflags;

	D( printf(" . Loading the server certs and key...\n"); )

	memset( &srvcert, 0, sizeof( x509_cert ) );
	memset( &ca_chain, 0, sizeof( x509_cert ) );

	ret = x509parse_crtfile( &srvcert, SRV_CERT_FILE);
	if( ret != 0 ) {
		printf("\t> Error: Invalid or missing server certificate (%s).\n", SRV_CERT_FILE);
		print_ssl_errors(ret);
		return ret;
	}

	ret = x509parse_crtfile( &ca_chain, CA_CERT_FILE);
	if( ret != 0 ) {
		printf("\t> Error: Invalid or missing CA certificate (%s).\n", CA_CERT_FILE);
		print_ssl_errors(ret);
		return ret;
	}

	ret = x509parse_keyfile( &rsa, SRV_KEY_FILE, NULL);
	if( ret != 0 ) {
		printf("\t> Error: Invalid or missing server key (%s).\n", SRV_KEY_FILE);
		print_ssl_errors(ret);
		return ret;
	}

	if (x509parse_verify(&srvcert, &ca_chain, NULL, NULL, &certflags) != 0) {
		printf("\t> Error: Certificate chain verification failed:");
		if (certflags & BADCERT_EXPIRED)		printf(" EXPIRED");
		if (certflags & BADCERT_NOT_TRUSTED)		printf(" NOT TRUSTED");
		printf("\n");
		return FAILURE;
	}

	D( printf( "  . Initializing TLS structure and RNG...." ); )

	havege_init( hs );

	memset( ssl, 0, sizeof( ssl ) );

	if( ( ret = ssl_init( ssl ) ) != 0 )
	{
		D( printf( " failed\n" ); )
		D( printf( " ERROR: ! ssl_init returned %d\n\n", ret ); )
		return ret;
	}

	D( printf( " ok\n" ); )

	ssl_set_endpoint( ssl, SSL_IS_SERVER );
	ssl_set_authmode( ssl, SSL_VERIFY_NONE );

	ssl_set_rng( ssl, havege_rand, hs );
	ssl_set_dbg( ssl, my_debug, stdout );
	ssl_set_bio( ssl, net_recv, sockfd, net_send, sockfd );
	ssl_set_scb( ssl, my_get_session, my_set_session );

	ssl_set_ciphers( ssl, ssl_default_ciphers );
	ssl_set_session( ssl, 1, 0, ssn );

	memset( ssn, 0, sizeof( ssl_session ) );

	ssl_set_ca_chain( ssl, &ca_chain, NULL, NULL );
	ssl_set_own_cert( ssl, &srvcert, &rsa );
	ssl_set_dh_param( ssl, my_dhm_P, my_dhm_G );

	return 0;

}
#endif
//*******************************************************
int crypt_cleanup( ssl_context *ssl )
{
    ssl_free( ssl );

#ifdef SSL_SERVER
	if ( ssl->endpoint == SSL_IS_SERVER )
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
#endif

    memset( ssl, 0, sizeof( ssl_context ) );

	return 0;
}

#ifdef __cplusplus
}
#endif
//*******************************************************
void print_ssl_errors(int error)
{
	if (error == POLARSSL_ERR_X509_FEATURE_UNAVAILABLE)		printf("X509 Error: Feature not available\n");
	if (error == POLARSSL_ERR_X509_CERT_INVALID_PEM)		printf("X509 Certificate Error: Invalid PEM format\n");
	if (error == POLARSSL_ERR_X509_CERT_INVALID_FORMAT)		printf("X509 Certificate Error: Invalid format\n");
	if (error == POLARSSL_ERR_X509_CERT_INVALID_VERSION)		printf("X509 Certificate Error: Invalid version\n");
	if (error == POLARSSL_ERR_X509_CERT_INVALID_SERIAL)		printf("X509 Certificate Error: Invalid serial number\n");

	if (error == POLARSSL_ERR_X509_CERT_INVALID_ALG)		printf("X509 Certificate Error: Invalid algorithm\n");
	if (error == POLARSSL_ERR_X509_CERT_INVALID_NAME)		printf("X509 Certificate Error: Invalid name\n");
	if (error == POLARSSL_ERR_X509_CERT_INVALID_DATE)		printf("X509 Certificate Error: Invalid date\n");
	if (error == POLARSSL_ERR_X509_CERT_INVALID_PUBKEY)		printf("X509 Certificate Error: Invalid public key\n");
	if (error == POLARSSL_ERR_X509_CERT_INVALID_SIGNATURE)		printf("X509 Certificate Error: Invalid signature\n");

	if (error == POLARSSL_ERR_X509_CERT_INVALID_EXTENSIONS)		printf("X509 Certificate Error: Invalid extensions\n");
	if (error == POLARSSL_ERR_X509_CERT_UNKNOWN_VERSION)		printf("X509 Certificate Error: Unknown version\n");
	if (error == POLARSSL_ERR_X509_CERT_UNKNOWN_SIG_ALG)		printf("X509 Certificate Error: Unknown signature algorithm\n");
	if (error == POLARSSL_ERR_X509_CERT_UNKNOWN_PK_ALG)		printf("X509 Certificate Error: Unknown algorithm\n");
	if (error == POLARSSL_ERR_X509_CERT_SIG_MISMATCH)		printf("X509 Certificate Error: Signature mismatch\n");

	if (error == POLARSSL_ERR_X509_CERT_VERIFY_FAILED)		printf("X509 Certificate Error: Verify failed\n");
	if (error == POLARSSL_ERR_X509_KEY_INVALID_PEM)			printf("X509 Key Error: Invalid X509 PEM format\n");
	if (error == POLARSSL_ERR_X509_KEY_INVALID_VERSION)		printf("X509 Key Error: Invalid version\n");
	if (error == POLARSSL_ERR_X509_KEY_INVALID_FORMAT)		printf("X509 Key Error: Invalid format\n");
	if (error == POLARSSL_ERR_X509_KEY_INVALID_ENC_IV)		printf("X509 Key Error: Invalid encoding initialization vector\n");

	if (error == POLARSSL_ERR_X509_KEY_UNKNOWN_ENC_ALG)		printf("X509 Key Error: Unknown encoding algorithm\n");
	if (error == POLARSSL_ERR_X509_KEY_PASSWORD_REQUIRED)		printf("X509 Key Error: Password required\n");
	if (error == POLARSSL_ERR_X509_KEY_PASSWORD_MISMATCH)		printf("X509 Key Error: Password mismatch\n");
	if (error == POLARSSL_ERR_X509_POINT_ERROR)			printf("X509 Error: Point error\n");
	if (error == POLARSSL_ERR_X509_VALUE_TO_LENGTH)			printf("X509 Error: Value to length error\n");
}
