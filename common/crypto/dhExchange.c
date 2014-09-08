//SERVER FILES
#ifndef _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

#include <string.h>
#include <stdio.h>

#include "polarssl/config.h"

#include "polarssl/net.h"
#include "polarssl/aes.h"
#include "polarssl/dhm.h"
#include "polarssl/rsa.h"
#include "polarssl/ssl.h"
#include "polarssl/sha1.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/debug.h"

int find_DH_SecretKey( ssl_context *ssl);
int dhClientExchange( ssl_context *ssl );
int dhServerExchange( ssl_context *ssl);

int find_DH_SecretKey( ssl_context *ssl)
{

	uint8_t *		kKey;
	size_t			kKeySize;
	int				mpiRet;
	//int				n;

	DL(4);
	if ((kKeySize = mpi_size(&(ssl->dhm_ctx.K))) > 0) {
		DLX(4, printf("kKeySize = %d\n", kKeySize));
		kKey= (uint8_t *) calloc(kKeySize, sizeof(uint8_t));
	}
	//TODO: Add error code here
	DL(4);
	memcpy(kKey, &(ssl->dhm_ctx.K), kKeySize);
	SSL_DEBUG_MPI( 3, "kKey:", (mpi *)kKey);

	DLX(4, printf( "kKey now has Length of %d.\n", kKeySize));

	DLX(4, printf("Freeing kKey for now...\n") );
	if (kKey != NULL)
		free( kKey);

	return mpiRet;
}



//Will use ssl_write and ssl_read since connection already exists.
////#define SERVER_PORT 11999
//#define PLAINTEXT "==Hello there!=="


//Will use ssl_write and ssl_read since connection already exists.
//#define SERVER_NAME "localhost"
//#define SERVER_PORT 11999



/////////////////////////////////////////////////////////////////////
//  CLIENT PORTION
//
/*
 *  Diffie-Hellman-Merkle key exchange (client side)
 *
 *  Copyright (C) 2006-2011, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#if !defined(POLARSSL_AES_C) || !defined(POLARSSL_DHM_C) ||     \
    !defined(POLARSSL_ENTROPY_C) || !defined(POLARSSL_NET_C) ||  \
    !defined(POLARSSL_RSA_C) || !defined(POLARSSL_SHA1_C) ||    \
    !defined(POLARSSL_FS_IO) || !defined(POLARSSL_CTR_DRBG_C)
int dhClientExchange( ssl_context *ssl )
{

    printf("POLARSSL_AES_C and/or POLARSSL_DHM_C and/or POLARSSL_ENTROPY_C "
           "and/or POLARSSL_NET_C and/or POLARSSL_RSA_C and/or "
           "POLARSSL_SHA1_C and/or POLARSSL_FS_IO and/or "
           "POLARSSL_CTR_DRBG_C not defined.\n");
    return( 0 );
}
#else

/*!	@brief Diffie-Hellman-Merkle Client Exchange
 *
 * @param ssl ssl context
 * @returns generated shared secret
 * @retval < 0 is an error
 */

int dhmClientExchange( ssl_context *ssl )
{
    int 	ret;
    size_t 	n, buflen;
    int 	server_fd = -1;

    unsigned char	*p, *end;
    unsigned char	buf[1024];
    char 			*pers = "dh_client";

    entropy_context		entropy;
    ctr_drbg_context	ctr_drbg;
    dhm_context			dhm;

    memset(&dhm, 0, sizeof( dhm ));	// Clear DHM context

	//Setup the RNG
    DLX(4, printf("Seeding the random number generator\n"));

    entropy_init( &entropy );
    if( ( ret = ctr_drbg_init( &ctr_drbg, entropy_func, &entropy, (unsigned char *) pers, strlen( pers ) ) ) != 0 )
    {
        DLX(4, printf("ctr_drbg_init failed, returned %d\n", ret));
        goto exit;
    }

	// First get the buffer length

    DLX(4, printf("Receiving the server's DH parameters\n"));

    memset(buf, 0, sizeof(buf));
    if (( ret = ssl_read( ssl, buf, 2 )) != 2 )
	{
    	DLX(4, printf("ssl_read() failed to receive buffer length, returned: %d\n", ret));
		goto exit;
	}

    buflen = ( buf[0] << 8 ) | buf[1];
    if( buflen < 1 || buflen > sizeof( buf ) )
    {
        DLX(4, printf("Received invalid buffer length: %d\n", buflen));
        goto exit;
    }

	// Get the DHM parameters: P, G and Ys = G^Xs mod P

    memset(buf, 0, sizeof( buf ));
    n = 0;
    do {
    	ret = ssl_read( ssl, buf, n );
    	if (ret < 0) {
    		DLX(4, printf(ssl_read() error: %d\n", ret"));
    		continue;
    	}
    	n += ret;
    } while (n < buflen);

    p = buf, end = buf + buflen;

    if( ( ret = dhm_read_params( &dhm, &p, end ) ) != 0 )
    {
        DLX(4, printf("dhm_read_params() failed, returned %d\n", ret ));
        goto exit;
    }

    if( dhm.len < 64 || dhm.len > 256 )
    {
        ret = -1;
        DLX(4, printf("Invalid DHM modulus size\n"));
        goto exit;
    }

	// Generate public value and send to server: Yc = G ^ Xc mod P
    DLX(4, printf("\Sending own public value to server\n"));

    n = dhm.len;
    if (( ret = dhm_make_public( &dhm, 256, buf, n, ctr_drbg_random, &ctr_drbg )) != 0 )
    {
        DLX(4, printf("dhm_make_public() failed, returned %d\n", ret));
        goto exit;
    }

    n = 0;
    do {
    	ret = ssl_write( ssl, buf, n );
    	if (ret < 0) {
    		DLX(4, printf(ssl_write() error: %d\n", ret"));
    		continue;
    	}
    	n += ret;
    } while (n < dhm.len);

	// Derive the shared secret: K = Ys ^ Xc mod P
    n = dhm.len;
    if( ( ret = dhm_calc_secret( &dhm, buf, &n ) ) != 0 )
    {
        DLX(4, printf( "dhm_calc_secret() failed, returned %d\n", ret));
        goto exit;
    }

    DLX(4, printf("Shared secret: ");
		for( n = 0; n < 16; n++ )
			printf( "%02x", buf[n] );
		printf("\n");
		);

#if 0
    /*
     * 8. Setup the AES-256 decryption key
     *
     * This is an overly simplified example; best practice is
     * to hash the shared secret with a random value to derive
     * the keying material for the encryption/decryption keys,
     * IVs and MACs.
     */
    printf( "...\n  . Receiving and decrypting the ciphertext" );
    fflush( stdout );

    aes_setkey_dec( &aes, buf, 256 );

    memset( buf, 0, sizeof( buf ) );

    if( ( ret = net_recv( &server_fd, buf, 16 ) ) != 16 )
    {
        printf( " failed\n  ! net_recv returned %d\n\n", ret );
        goto exit;
    }

    aes_crypt_ecb( &aes, AES_DECRYPT, buf, buf );
    buf[16] = '\0';
    printf( "\n  . Plaintext is \"%s\"\n\n", (char *) buf );
#endif

exit:
    net_close( server_fd );
    dhm_free( &dhm );
    return( ret );
}

#endif /* POLARSSL_AES_C && POLARSSL_DHM_C && POLARSSL_ENTROPY_C &&
          POLARSSL_NET_C && POLARSSL_RSA_C && POLARSSL_SHA1_C && 
          POLARSSL_FS_IO && POLARSSL_CTR_DRBG_C */

//
//  END OF CLIENT PORTION
/////////////////////////////////////////////////////////////////////



/////////////////////////////////////////////////////////////////////
//  SERVER PORTION
//

/*
 *  Diffie-Hellman-Merkle key exchange (server side)
 *
 *  Copyright (C) 2006-2011, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#if !defined(POLARSSL_AES_C) || !defined(POLARSSL_DHM_C) ||     \
    !defined(POLARSSL_ENTROPY_C) || !defined(POLARSSL_NET_C) ||  \
    !defined(POLARSSL_RSA_C) || !defined(POLARSSL_SHA1_C) ||    \
    !defined(POLARSSL_FS_IO) || !defined(POLARSSL_CTR_DRBG_C)
int dhServerExchange( ssl_context *ssl )
{
    printf("POLARSSL_AES_C and/or POLARSSL_DHM_C and/or POLARSSL_ENTROPY_C "
           "and/or POLARSSL_NET_C and/or POLARSSL_RSA_C and/or "
           "POLARSSL_SHA1_C and/or POLARSSL_FS_IO and/or "
           "POLARSSL_CTR_DBRG_C not defined.\n");
    return( 0 );
}
#else
/*!	@brief Diffie-Hellman-Merkle Server Exchange
 *
 * @param ssl ssl context
 * @returns generated shared secret
 * @retval < 0 is an error
 */
int dhmServerExchange( ssl_context *ssl )
{
    FILE *f;  

    int ret, retA;
    size_t n, buflen;

    unsigned char buf[1024];
    unsigned char hash[20];
    unsigned char buf2[2];
    char *pers = "dh_server";

    entropy_context		entropy;
    ctr_drbg_context	ctr_drbg;
    dhm_context			dhm;
    //aes_context aes;

    memset(&dhm, 0, sizeof(dhm));	// Clear DHM context

	//	Setup the RNG
    printf( "\n  . Seeding the random number generator" );
    fflush( stdout );

    entropy_init( &entropy );
    if( ( ret = ctr_drbg_init( &ctr_drbg, entropy_func, &entropy,
                               (unsigned char *) pers, strlen( pers ) ) ) != 0 )
    {
        printf( " failed\n  ! ctr_drbg_init returned %d\n", ret );
        goto exit;
    }

    /*
     * 2a. Read the server's private RSA key
     */
    printf( "\n  ****** Removed reading private key from rsa_priv.txt" );
    fflush( stdout );

#if 0
    if( ( f = fopen( "rsa_priv.txt", "rb" ) ) == NULL )
    {
        ret = 1;
        printf( " failed\n  ! Could not open rsa_priv.txt\n" \
                "  ! Please run rsa_genkey first\n\n" );
        goto exit;
    }

    rsa_init( &rsa, RSA_PKCS_V15, 0 );

    if( ( ret = mpi_read_file( &rsa.N , 16, f ) ) != 0 ||
        ( ret = mpi_read_file( &rsa.E , 16, f ) ) != 0 ||
        ( ret = mpi_read_file( &rsa.D , 16, f ) ) != 0 ||
        ( ret = mpi_read_file( &rsa.P , 16, f ) ) != 0 ||
        ( ret = mpi_read_file( &rsa.Q , 16, f ) ) != 0 ||
        ( ret = mpi_read_file( &rsa.DP, 16, f ) ) != 0 ||
        ( ret = mpi_read_file( &rsa.DQ, 16, f ) ) != 0 ||
        ( ret = mpi_read_file( &rsa.QP, 16, f ) ) != 0 )
    {
        printf( " failed\n  ! mpi_read_file returned %d\n\n", ret );
        goto exit;
    }

    rsa.len = ( mpi_msb( &rsa.N ) + 7 ) >> 3;
    
    fclose( f );
#endif

    /*
     * 2b. Get the DHM modulus and generator
     */
    printf( "\n  . Reading DH parameters from dh_prime.txt" );
    fflush( stdout );

    if( ( f = fopen( "dh_prime.txt", "rb" ) ) == NULL )
    {
        ret = 1;
        printf( " failed\n  ! Could not open dh_prime.txt\n" \
                "  ! Please run dh_genprime first\n\n" );
        goto exit;
    }

    if( mpi_read_file( &dhm.P, 16, f ) != 0 ||
        mpi_read_file( &dhm.G, 16, f ) != 0 )
    {
        printf( " failed\n  ! Invalid DH parameter file\n\n" );
        goto exit;
    }

    fclose( f );

	//NOT DONE SINCE ssl_write and ssl_read are available
#if 0
    /*
     * 3. Wait for a client to connect
     */
    printf( "\n  . Waiting for a remote connection" );
    fflush( stdout );

    if( ( ret = net_bind( &listen_fd, NULL, SERVER_PORT ) ) != 0 )
    {
        printf( " failed\n  ! net_bind returned %d\n\n", ret );
        goto exit;
    }

    if( ( ret = net_accept( listen_fd, &client_fd, NULL ) ) != 0 )
    {
        printf( " failed\n  ! net_accept returned %d\n\n", ret );
        goto exit;
    }
#endif 

    /*
     * 4. Setup the DH parameters (P,G,Ys)
     */
    printf( "\n  . Sending the server's DH parameters" );
    fflush( stdout );

    memset( buf, 0, sizeof( buf ) );

    if( ( ret = dhm_make_params( &dhm, 256, buf, &n,
                                 ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        printf( " failed\n  ! dhm_make_params returned %d\n\n", ret );
        goto exit;
    }

    /*
     * 5. Sign the parameters and send them
     */
    sha1( buf, n, hash );

    buf[n    ] = (unsigned char)( rsa.len >> 8 );
    buf[n + 1] = (unsigned char)( rsa.len      );

#if 0
    if( ( ret = rsa_pkcs1_sign( &rsa, NULL, NULL, RSA_PRIVATE, SIG_RSA_SHA1,
                                0, hash, buf + n + 2 ) ) != 0 )
    {
        printf( " failed\n  ! rsa_pkcs1_sign returned %d\n\n", ret );
        goto exit;
    }
    buflen = n + 2 + rsa.len;
#endif
	buflen = n + 2;
    buf2[0] = (unsigned char)( buflen >> 8 );
    buf2[1] = (unsigned char)( buflen      );

    //if( ( ret = net_send( &client_fd, buf2, 2 ) ) != 2 ||
    //    ( ret = net_send( &client_fd, buf, buflen ) ) != (int) buflen )
    //{
    //    printf( " failed\n  ! net_send returned %d\n\n", ret );
    //    goto exit;
    //}
    //  May need to use ssl->f_send(ssl->p_send, buf2, 2)
	if ( ( ( retA = ssl_write( ssl, buf2, 2 ) ) != 0) || 
        ( ret = ssl_write( ssl, buf, buflen) != 0) )
	{
		if (retA != 0)
		{ 
			printf(" Server dh 5a filed.\n");
		}
		else
		{
			if (ret != 0)
			{
				printf(" Server dh 5b failed.\n");
			}
		}
	}
	else
	{
		printf(" Server dh 5 a and b suceeded.\n");
	}

    /*
     * 6. Get the client's public value: Yc = G ^ Xc mod P
     */
    printf( "\n  . Receiving the client's public value" );
    fflush( stdout );

    memset( buf, 0, sizeof( buf ) );
    n = dhm.len;

    //if( ( ret = net_recv( &client_fd, buf, n ) ) != (int) n )
    //{
    //    printf( " failed\n  ! net_recv returned %d\n\n", ret );
    //    goto exit;
    //}
    //  May need to use ssl->f_recv(ssl->p_recv, buf, n)
	if ( ( ret = ssl_read( ssl, buf, n ) ) != 0 )
	{
		if (ret != 0)
		{
			printf(" Server dh 6 failed.\n");
		}
	}
	else
	{
		printf(" Server dh 6 suceeded.\n");
	}
		
    if( ( ret = dhm_read_public( &dhm, buf, dhm.len ) ) != 0 )
    {
        printf( " failed\n  ! dhm_read_public returned %d\n\n", ret );
        goto exit;
    }

    /*
     * 7. Derive the shared secret: K = Ys ^ Xc mod P
     */
    printf( "\n  . Shared secret: " );
    fflush( stdout );

    if( ( ret = dhm_calc_secret( &dhm, buf, &n ) ) != 0 )
    {
        printf( " failed\n  ! dhm_calc_secret returned %d\n\n", ret );
        goto exit;
    }

    for( n = 0; n < 16; n++ )
        printf( "%02x", buf[n] );

#if 0
    /*
     * 8. Setup the AES-256 encryption key
     *
     * This is an overly simplified example; best practice is
     * to hash the shared secret with a random value to derive
     * the keying material for the encryption/decryption keys
     * and MACs.
     */
    printf( "...\n  . Encrypting and sending the ciphertext" );
    fflush( stdout );

    aes_setkey_enc( &aes, buf, 256 );
    memcpy( buf, PLAINTEXT, 16 );
    aes_crypt_ecb( &aes, AES_ENCRYPT, buf, buf );

    if( ( ret = net_send( &client_fd, buf, 16 ) ) != 16 )
    {
        printf( " failed\n  ! net_send returned %d\n\n", ret );
        goto exit;
    }

    printf( "\n\n" );
#endif

exit:

    rsa_free( &rsa );
    dhm_free( &dhm );

#if defined(_WIN32)
    printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
#endif /* POLARSSL_AES_C && POLARSSL_DHM_C && POLARSSL_ENTROPY_C &&
          POLARSSL_NET_C && POLARSSL_RSA_C && POLARSSL_SHA1_C &&
          POLARSSL_FS_IO && POLARSSL_CTR_DRBG_C */

//
//  END OF SERVER PORTION
/////////////////////////////////////////////////////////////////////


