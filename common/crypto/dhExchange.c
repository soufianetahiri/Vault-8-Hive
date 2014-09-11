//SERVER FILES
#ifndef _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

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
#include "dhExchange.h"
#include "debug.h"

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
#ifdef SSL_DEBUG_MPI
	SSL_DEBUG_MPI( 3, "kKey:", (mpi *)kKey);
#endif
	DLX(4, printf( "kKey now has Length of %d.\n", kKeySize));

	DLX(4, printf("Freeing kKey for now...\n") );
	if (kKey != NULL)
		free( kKey);

	return mpiRet;
}

/*!
 * @brief dhHandshake performs a Diffie Hellman key exchange
 * @param ssl SSL context
 * @return
 * @retval 0 Error, shared secret not created
 */
dhm_context *dhHandshake(ssl_context *ssl )
{
	if ( ssl->endpoint == SSL_IS_CLIENT )
	{
		DLX(4, printf( "Performing dhClientExchange\n"));
		return (dhClientExchange( ssl ));
	}
	else
	{
		DLX(4, printf( "Performing dhServerExchange\n"));
		return (dhServerExchange( ssl ));
	}
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

dhm_context *dhClientExchange( ssl_context *ssl )
{
    int 	ret;
    size_t 	n, buflen;
    int 	server_fd = -1;

    unsigned char	*p, *end;
    unsigned char	buf[1024];
    char 			*pers = "dh_client";

    entropy_context		entropy;
    ctr_drbg_context	ctr_drbg;
    dhm_context			*dhm;

    if ( (dhm = calloc(1, sizeof(dhm_context)) ) == NULL)
    		return NULL;

	//Setup the RNG
    DLX(4, printf("Seeding the random number generator\n"));
    entropy_init(&entropy);
    if ((ret = ctr_drbg_init(&ctr_drbg, entropy_func, &entropy, (unsigned char *) pers, strlen(pers))) != 0)
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
    DLX(4, printf("Waiting to receive %d bytes\n", buflen));
    if( buflen < 1 || buflen > sizeof( buf ) )
    {
        DLX(4, printf("Received invalid buffer length: %d\n", buflen));
        goto exit;
    }

	// Get the DHM parameters: P, G and Ys = G^Xs mod P

    memset(buf, 0, sizeof(buf));
    n = 0;
    do {
    	ret = ssl_read( ssl, buf+n, buflen-n );
    	if (ret < 0) {
    		DLX(4, printf("ssl_read() error: %d\n", ret));
    		continue;
    	}
    	n += ret;
    } while (n < buflen);

	DPB(4, "Received buffer follows:", "\t", buf, buflen);
    p = buf, end = buf + buflen;

    DLX(4, printf("Received DHM params: %d bytes -- calling dhm_read_params()\n", n));
    if( ( ret = dhm_read_params( dhm, &p, end ) ) != 0 )
    {
        DLX(4, printf("dhm_read_params() failed, returned %0x\n", ret ));
        goto exit;
    }

    if( dhm->len < 64 || dhm->len > 256 )
    {
        ret = -1;
        DLX(4, printf("Invalid DHM modulus size\n"));
        goto exit;
    }

	// Generate public value and send to server: Yc = G ^ Xc mod P
    DLX(4, printf("Sending own public value to server\n"));

    buflen = dhm->len;
    if (( ret = dhm_make_public( dhm, 256, buf, buflen, ctr_drbg_random, &ctr_drbg )) != 0 )
    {
        DLX(4, printf("dhm_make_public() failed, returned %d\n", ret));
        goto exit;
    }
    DPB(4, "DHM Parameters:", "\t", buf, buflen);
    n = 0;
    do {
    	ret = ssl_write( ssl, buf+n, buflen-n );
    	if (ret < 0) {
    		DLX(4, printf("ssl_write() error: %d\n", ret));
    		continue;
    	}
    	n += ret;
    } while (n < dhm->len);

	// Derive the shared secret: K = Ys ^ Xc mod P
    n = dhm->len;
    if( ( ret = dhm_calc_secret( dhm, buf, &n ) ) != 0 )
    {
        DLX(4, printf( "dhm_calc_secret() failed, returned %d\n", ret));
        goto exit;
    }

    DPB(4, "Shared Secret:\n", "\t", buf, n);

    return(dhm);

#if 0
    DLX(4, printf("Shared secret:");
		for( n = 0; n < 16; n++ )
			printf( "%02x", buf[n] );
		printf("\n");
		);
#endif
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
    dhm_free( dhm );
    return(NULL);
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
dhm_context *dhServerExchange( ssl_context *ssl )
{
    int			ret;
    size_t		n, buflen;

	unsigned char buf[1024];
	unsigned char buf2[2];
	char *pers = "dh_server";

    entropy_context		entropy;
    ctr_drbg_context	ctr_drbg;
    dhm_context			*dhm;

    if ( (dhm = calloc(1, sizeof(dhm_context)) ) == NULL)
    		return NULL;

	//	Setup the RNG
    DLX(4, printf("Seeding the random number generator\n"));
    entropy_init(&entropy);

    if ((ret = ctr_drbg_init(&ctr_drbg, entropy_func, &entropy, (unsigned char *) pers, strlen(pers))) != 0)
    {
        DLX(4, printf("ctr_drbg_init() failed, returned: %d\n", ret));
        goto exit;
    }

	// Get the DHM modulus and generator
    DLX(4, printf("Reading P\n"));
    if ((ret = mpi_read_string(&dhm->P, 16, POLARSSL_DHM_RFC3526_MODP_2048_P)) != 0 ) {
    	DLX(4, printf("mpi_read_string() failed, returned: %d\n", ret));
    	goto exit;
    }
    DLX(4, printf("Reading G\n"));
    if ((ret = mpi_read_string(&dhm->G, 16, POLARSSL_DHM_RFC3526_MODP_2048_G)) != 0 ) {
    	DLX(4, printf("mpi_read_string() failed, returned: %d\n", ret));
    	goto exit;
    }

	// Setup the DH parameters (P,G,Ys)

    DLX(4, printf("Sending the server's DH parameters\n"));

    memset( buf, 0, sizeof(buf));	// Clear buffer

    if (( ret = dhm_make_params( dhm, 256, buf, &buflen, ctr_drbg_random, &ctr_drbg)) != 0 )
    {
        DLX(4, printf("dhm_make_params() failed, returned: %d\n", ret));
        goto exit;
    }

    /*
     * 5. Sign the parameters and send them
     */
    //sha1( buf, n, hash );

    //buf[n    ] = (unsigned char)( rsa.len >> 8 );
    //buf[n + 1] = (unsigned char)( rsa.len      );

	//buflen = n + 2;

    buf2[0] = (unsigned char)( buflen >> 8 );
    buf2[1] = (unsigned char)( buflen      );

    // Send the buffer length to the client
    DLX(4, printf("Sending buffer of length: %d\n", buflen));
	if ( (ret = ssl_write( ssl, buf2, 2)) != 2) {
		DLX(4, printf("ssl_write() failed to send buffer length to client. Returned: %d\n", ret));
		goto exit;
	}

	// Send the buffer to the client
    n = 0;
    do {
    	ret = ssl_write( ssl, buf+n, buflen-n );
    	if (ret < 0) {
    		DLX(4, printf("ssl_write() error: %d\n", ret));
    		continue;
    	} else
    		DLX(4, printf("Wrote %d bytes\n", ret));
    	n += ret;
    } while (n < buflen);

	DPB(4, "Buffer sent follows:", "\t", buf, buflen);

	// Get the client's public value: Yc = G ^ Xc mod P

    DLX (4, printf("Receiving the client's public value\n"));

    memset(buf, 0, sizeof(buf));	// Clear buffer
    n = 0;
    do {
    	ret = ssl_read( ssl, buf+n, buflen-n );
    	if (ret < 0) {
    		DLX(4, printf("ssl_read() error: %d\n", ret));
    		continue;
    	}
    	n += ret;
    } while (n < buflen);
		
    if ((ret = dhm_read_public( dhm, buf, dhm->len )) != 0 )
    {
		DLX(4, printf("dhm_read_public() error: %d\n", ret));
        goto exit;
    }

	// Derive the shared secret: K = Ys ^ Xc mod P

    if( ( ret = dhm_calc_secret( dhm, buf, &n ) ) != 0 )
    {
        DLX(4, printf("dhm_calc_secret() failed, returned %d\n", ret));
        goto exit;
    }
#ifdef SSL_DEBUG_BUF
    SSL_DEBUG_BUF(3, "Shared Secret: ", buf, n);
#endif
    return(dhm);

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
    dhm_free( dhm );
    free(dhm);
    return(NULL);

}
#endif /* POLARSSL_AES_C && POLARSSL_DHM_C && POLARSSL_ENTROPY_C &&
          POLARSSL_NET_C && POLARSSL_RSA_C && POLARSSL_SHA1_C &&
          POLARSSL_FS_IO && POLARSSL_CTR_DRBG_C */

//
//  END OF SERVER PORTION
/////////////////////////////////////////////////////////////////////


