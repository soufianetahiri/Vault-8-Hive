#ifdef __cplusplus
extern "C" {
#endif

#include "crypto.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "crypto_proj_strings.h"
#include "polarssl/x509.h"
#include "polarssl/aes.h"

//#include "dhExchange.c"

entropy_context entropy;		// Entropy context
ctr_drbg_context ctr_drbg;		// Counter mode deterministic random byte generator context
const char *personalization = "7ddc11c4-5789-44d4-8de4-88c0d23d4029";	// Custom data to add uniqueness

enum {FALSE = 0, TRUE} rng_initialized;

char *my_dhm_P = (char *) my_dhm_P_String;	// The values of these strings are located in crypto_strings.txt
char *my_dhm_G = (char *) my_dhm_G_String;


static int my_set_session(ssl_context * ssl);
static int my_get_session(ssl_context * ssl);

//*******************************************************
#ifndef DEBUG
#define DEBUG_LEVEL 0
#endif
//*******************************************************
void my_debug(void *ctx, int level, const char *str) {
#ifdef DEBUG
	if (level < dbug_level_)
#else
	if (level < DEBUG_LEVEL)
#endif
	{
		fprintf((FILE *) ctx, "%s", str);
		fflush((FILE *) ctx);
	}
}

//*******************************************************

void rng_init()
{
	D(int ret);

	DLX(6, printf( "Initializing RNG.\n"));
	if ( (D(ret =) ctr_drbg_init(&ctr_drbg, entropy_func, &entropy, (unsigned const char *)personalization, strlen(personalization))) != 0 ) {
		DLX(4, switch (ret) {
					case POLARSSL_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED:	printf("The entropy source failed.\n"); break;
					case POLARSSL_ERR_CTR_DRBG_REQUEST_TOO_BIG:			printf("Too many random requested in single call."); break;
					case POLARSSL_ERR_CTR_DRBG_INPUT_TOO_BIG:			printf("Input too large (Entropy + additional).\n"); break;
					case POLARSSL_ERR_CTR_DRBG_FILE_IO_ERROR:			printf("Read/write error in file\n"); break;
					default:											printf("ERROR: ctr_drbg_init() failed, returned -0x%04x\n", -ret);}
				);
		if ((D(ret =)ctr_drbg_update_seed_file(&ctr_drbg, ".seedfile")) !=0 ) {
			DLX(4, switch (ret) {
				case POLARSSL_ERR_CTR_DRBG_FILE_IO_ERROR:			printf("Failed to open seed file.\n"); break;
				case POLARSSL_ERR_CTR_DRBG_REQUEST_TOO_BIG:			printf("Seed file too big?.\n"); break;
				case POLARSSL_ERR_CTR_DRBG_INPUT_TOO_BIG:			printf("Seed file too big?.\n"); break;
				case POLARSSL_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED:	printf("The entropy source failed.\n"); break;
				default:											printf("ERROR: ctr_drbg_update_seedfile() failed, returned -0x%04x\n", -ret);
				}
			);
		}
	}
	ctr_drbg_set_prediction_resistance(&ctr_drbg, CTR_DRBG_PR_OFF);	// Turn off prediction resistance
	rng_initialized = TRUE;
	return;
}

void gen_random(unsigned char *output, size_t output_len)
{
	if (!rng_initialized)
		rng_init();

if ((ctr_drbg_random( &ctr_drbg, output, output_len)) != 0 )
	return;

}

//*******************************************************
int crypt_handshake(ssl_context * ssl) {
		int ret;
		/*
		 * 5. Handshake
		 */
		DLX(4, printf("\tPerforming the TLS handshake... \n"));

		while ((ret = ssl_handshake(ssl)) != 0) {
			if (ret != POLARSSL_ERR_NET_WANT_WRITE) {
				DLX(4, printf("TLS handshake failed, returned: -0x%04x\n", -ret));
				return -1;
			}
		}

		DLX(4, printf("\tTLS handshake complete\n"));

		return 0;
	}

//*******************************************************
#if 0							// Proposed new code
	int crypt_write(ssl_context * ssl, unsigned char *buf, int size) {
		int ret = 0;
		int sent = 0;

		DL(4);
		do {
			ret = ssl_write(ssl, buf + sent, size);
			if (ret == POLARSSL_ERR_NET_WANT_WRITE) {
				DLX(4, printf("POLARSSL_ERR_NET_WANT_WRITE\n"));
				continue;
			} else if (ret < 0) {
				DLX(4, printf("failed: ret = %0x, %d bytes sent\n", ret, sent));
				return ret;
			}
			size -= ret;
			sent += ret;
		} while (size);
		return (sent);
	}
#endif

//*******************************************************
int crypt_write(ssl_context * ssl, unsigned char *buf, int size) {
	int ret;

#if 0
	int 	dhRet;
	int 	aesRet;
	aes_context aes;
    unsigned char aeskey[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}; 
	//unsigned char testBuf[]="Hello World    \0";
	#define PLAINTEXT  "==Hello there!=="

	unsigned char *testBuf;
	unsigned char *encBuf;
	testBuf= (unsigned char *) calloc(16, sizeof(unsigned char));
	memcpy( testBuf, PLAINTEXT, 16);

	//encrypted buffer initialization
	encBuf= (unsigned char *) calloc(16, sizeof(unsigned char));
	DLX(4, printf("encBuf = %p\n", encBuf));
	if (encBuf == NULL)
	{
		DLX(4, printf( "encBuf Failed calloc.\n"));
	}
	DL(4);

    //dh Exchange will occur here using dhExchange.c and ssl_write with
    //ssl_read.
	if ( ssl->endpoint == SSL_IS_CLIENT )
	{
		DLX(4, printf( "Will attempt dhClientExchange.\n"));49630be
		//dhClientExchange( ssl );
	}
	else
	{
		DLX(4, printf( "Will attempt dhServerExchange.\n"));
		//dhServerExchange( ssl );
	}
	dhRet = 0;

	//Aes exChange will occur here...
	DLX(4, printf( "AES encryption occurs here.\n"));
	if ( aes_setkey_enc( &aes, aeskey, 128 ) == 0)
	{
		DLX(4, printf( "clearBuf->%s\n", testBuf));
		aesRet = aes_crypt_ecb( &aes, AES_ENCRYPT, testBuf, encBuf);
		DLX(4, printf( "STATUS: aes_crypt_ecb returned %d\n\n", aesRet));
		if ( aesRet == 0)
		{
			DLX(4, printf( "STATUS: aes_crypt_ecb success, returned %d\n\n", aesRet));
			{
				int i;
				for (i=0; i<size; i++)
					printf("%p: %2.2x ", encBuf+i, *(encBuf+i));
			}
			printf("\n");
			DLX(4, printf( "Encrypted encBuf->%x\n\n", encBuf));
		}
		else
		{
			DLX(4, printf( "ERROR: aes_crypt_ecb failed, returned %d\n\n", aesRet));
		}
		aes_setkey_dec( &aes, aeskey, 128 );
		aes_crypt_ecb( &aes, AES_DECRYPT, encBuf, testBuf);
		DLX(4, printf( "Decrypted encBuf->%s\n\n\n\n", testBuf));
	}
	else
	{
		DLX(4, printf( "ERROR: aes_setkey_enc failed\n\n", encBuf));
	}

	//Destroy encBuf
    if (encBuf != NULL)
	{
	    DLX(4, printf("encBuf = %p\n", encBuf));
	    DLX(4, printf("Deleting encBuf...\n"));
	    free(encBuf);
	}
	else
	{
		DLX(4, printf( " SHOULD NEVER HAVE GOTTEN HERE IN CRYPT_WRITE\n" ));
	}

#endif

	DL(4);

	while ((ret = ssl_write(ssl, buf, size)) <= 0) {
		if (ret != POLARSSL_ERR_NET_WANT_WRITE) {
			DLX(4, printf(" failed. ssl_write() returned -0x%04x\n", -ret));
			return ret;
		}
	}

	DLX(4, printf(" %d bytes written\n", ret));
	return ret;

}

//*******************************************************
int crypt_read(ssl_context * ssl, unsigned char *buf, int bufsize) {
	int ret;

	DL(6);

	do {
		memset(buf, 0, bufsize);

		ret = ssl_read(ssl, buf, bufsize);

		if (ret == POLARSSL_ERR_NET_WANT_READ) {
			DLX(4, printf("POLARSSL_ERR_NET_WANT_READ\n"));
			continue;
		}

		if (ret == POLARSSL_ERR_SSL_PEER_CLOSE_NOTIFY) {
			DLX(4, printf("POLARSSL_ERR_SSL_PEER_CLOSE_NOTIFY\n"));
			break;
		}

		if (ret <= 0) {
			DLX(4, printf("ERROR: crypt_read() failed. ssl_read returned -0x%04x\n", -ret));
			break;
		}

		DLX(6, printf("crypt_read(): %d bytes read\n", ret));
	}
	while (0);

	return ret;
}

//*******************************************************
int crypt_close_notify(ssl_context * ssl) {
	return ssl_close_notify(ssl);
}

//*******************************************************
int crypt_setup_client(ssl_context *ssl, ssl_session *ssn, int *sockfd) {
	int ret;

	if (! rng_initialized)	// Verify that the RNG is initialized.
		rng_init();

	memset(ssn, 0, sizeof(ssl_session));

	DLX(4, printf("\tInitializing the TLS structure...\n"));
	if ((ret = ssl_init(ssl)) != 0) {
		DLX(4, printf(" failed, ssl_init returned: -0x%04x\n", -ret));
		return -1;
	}
	DLX(4, printf(" ok\n"));

	ssl_set_endpoint(ssl, SSL_IS_CLIENT);
	ssl_set_authmode(ssl, SSL_VERIFY_NONE);

	ssl_set_rng(ssl, ctr_drbg_random, &ctr_drbg);
	ssl_set_dbg(ssl, my_debug, stdout);
	ssl_set_bio(ssl, net_recv, sockfd, net_send, sockfd);

	ssl_set_ciphersuites(ssl, ssl_default_ciphersuites);
	ssl_set_session(ssl, 1, 600, ssn);

	return 0;
}

#if 0
// = ssl_default_ciphers;
	int my_ciphers[] = {
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
int crypt_setup_server(ssl_context * ssl, ssl_session * ssn, int *sockfd) {
	int ret;
	int certflags;

	DLX(4, printf(" . Loading the server certs and key...\n"));

	memset(&srvcert, 0, sizeof(x509_cert));
	memset(&ca_chain, 0, sizeof(x509_cert));

	ret = x509parse_crtfile(&srvcert, SRV_CERT_FILE);
	if (ret != 0) {
		printf("\t> Error: Invalid or missing server certificate (%s).\n", SRV_CERT_FILE);
		print_ssl_errors(ret);
		return ret;
	}

	ret = x509parse_crtfile(&ca_chain, CA_CERT_FILE);
	if (ret != 0) {
		printf("\t> Error: Invalid or missing CA certificate (%s).\n", CA_CERT_FILE);
		print_ssl_errors(ret);
		return ret;
	}

	ret = x509parse_keyfile(&rsa, SRV_KEY_FILE, NULL);
	if (ret != 0) {
		printf("\t> Error: Invalid or missing server key (%s).\n", SRV_KEY_FILE);
		print_ssl_errors(ret);
		return ret;
	}

	if (x509parse_verify(&srvcert, &ca_chain, NULL, NULL, &certflags, NULL, NULL) != 0) {
		printf("\t> Error: Certificate chain verification failed:");
		if (certflags & BADCERT_EXPIRED)
			printf(" EXPIRED");
		if (certflags & BADCERT_NOT_TRUSTED)
			printf(" NOT TRUSTED");
		printf("\n");
		return -1;
	}

	if (! rng_initialized)	// Verify that the RNG is initialized.
		rng_init();

	memset(ssl, 0, sizeof(ssl));

	if ((ret = ssl_init(ssl)) != 0) {
		DLX(4, printf(" failed, ssl_init() returned -0x%04x\n\n", -ret));
		return ret;
	}

	ssl_set_endpoint(ssl, SSL_IS_SERVER);
	ssl_set_authmode(ssl, SSL_VERIFY_NONE);

	ssl_set_rng(ssl, ctr_drbg_random, &ctr_drbg);
	ssl_set_dbg(ssl, my_debug, stdout);
	ssl_set_bio(ssl, net_recv, sockfd, net_send, sockfd);
	ssl_set_scb(ssl, my_get_session, my_set_session);

	ssl_set_ciphersuites(ssl, ssl_default_ciphersuites);
	ssl_set_session(ssl, 1, 0, ssn);

	memset(ssn, 0, sizeof(ssl_session));

	ssl_set_ca_chain(ssl, &ca_chain, NULL, NULL);
	ssl_set_own_cert(ssl, &srvcert, &rsa);
	if (ssl_set_dh_param(ssl, my_dhm_P, my_dhm_G) != 0) {
		DLX(1, printf("INTERNAL ERROR: Unable to set DH parameters, check if init_crypto_strings() was called.\n"));
		return -1;
	}
	DLX(4, printf(" . SSL Server setup complete\n"));
	return 0;

}
//#endif
//#ifdef SSL_SERVER

//*******************************************************
/*
 * These session callbacks use a simple chained list
 * to store and retrieve the session information.
 */
	ssl_session *s_list_1st = NULL;
	ssl_session *cur, *prv;

//*******************************************************
static int my_get_session(ssl_context * ssl) {
	time_t t = time(NULL);

	if (ssl->resume == 0)
		return (1);

	cur = s_list_1st;
	prv = NULL;

	while (cur != NULL) {
		prv = cur;
		cur = cur->next;

		if (ssl->timeout != 0 && t - prv->start > ssl->timeout)
			continue;

		if (ssl->session->ciphersuite != prv->ciphersuite || ssl->session->length != prv->length)
			continue;

		if (memcmp(ssl->session->id, prv->id, prv->length) != 0)
			continue;

		memcpy(ssl->session->master, prv->master, 48);
		return (0);
	}

	return (1);
}

//*******************************************************
static int my_set_session(ssl_context * ssl) {
	time_t t = time(NULL);

	cur = s_list_1st;
	prv = NULL;

	while (cur != NULL) {
		if (ssl->timeout != 0 && t - cur->start > ssl->timeout)
			break;			/* expired, reuse this slot */

		if (memcmp(ssl->session->id, cur->id, cur->length) == 0)
			break;			/* client reconnected */

		prv = cur;
		cur = cur->next;
	}

	if (cur == NULL) {
		cur = (ssl_session *) malloc(sizeof(ssl_session));
		if (cur == NULL)
			return (1);

		if (prv == NULL)
			s_list_1st = cur;
		else
			prv->next = cur;
	}

	memcpy(cur, ssl->session, sizeof(ssl_session));

	return (0);
}
//#endif

//*******************************************************
int crypt_cleanup(ssl_context * ssl) {
	ssl_free(ssl);

	memset(ssl, 0, sizeof(ssl_context));

	return 0;
}

#ifdef __cplusplus
}
#endif

//*******************************************************
void print_ssl_errors(int error)
{
	switch(error) {

	case POLARSSL_ERR_X509_FEATURE_UNAVAILABLE:		printf("X509 Error: Feature not available\n");						break;
	case POLARSSL_ERR_X509_CERT_INVALID_PEM:		printf("X509 Certificate Error: Invalid PEM format\n");				break;
	case POLARSSL_ERR_X509_CERT_INVALID_FORMAT:		printf("X509 Certificate Error: Invalid format\n");					break;
	case POLARSSL_ERR_X509_CERT_INVALID_VERSION:	printf("X509 Certificate Error: Invalid version\n");				break;
	case POLARSSL_ERR_X509_CERT_INVALID_SERIAL:		printf("X509 Certificate Error: Invalid serial number\n");			break;

	case POLARSSL_ERR_X509_CERT_INVALID_ALG:		printf("X509 Certificate Error: Invalid algorithm\n");				break;
	case POLARSSL_ERR_X509_CERT_INVALID_NAME:		printf("X509 Certificate Error: Invalid name\n");					break;
	case POLARSSL_ERR_X509_CERT_INVALID_DATE:		printf("X509 Certificate Error: Invalid date\n");					break;
	case POLARSSL_ERR_X509_CERT_INVALID_PUBKEY:		printf("X509 Certificate Error: Invalid public key\n");				break;
	case POLARSSL_ERR_X509_CERT_INVALID_SIGNATURE:	printf("X509 Certificate Error: Invalid signature\n");				break;

	case POLARSSL_ERR_X509_CERT_INVALID_EXTENSIONS:	printf("X509 Certificate Error: Invalid extensions\n");				break;
	case POLARSSL_ERR_X509_CERT_UNKNOWN_VERSION:	printf("X509 Certificate Error: Unknown version\n");				break;
	case POLARSSL_ERR_X509_CERT_UNKNOWN_SIG_ALG:	printf("X509 Certificate Error: Unknown signature algorithm\n");	break;
	case POLARSSL_ERR_X509_UNKNOWN_PK_ALG:			printf("X509 Error: Unknown algorithm\n");							break;
	case POLARSSL_ERR_X509_CERT_SIG_MISMATCH:		printf("X509 Certificate Error: Signature mismatch\n");				break;

	case POLARSSL_ERR_X509_CERT_VERIFY_FAILED:		printf("X509 Certificate Error: Verify failed\n");					break;
	case POLARSSL_ERR_X509_KEY_INVALID_VERSION:		printf("X509 Key Error: Invalid version\n");						break;
	case POLARSSL_ERR_X509_KEY_INVALID_FORMAT:		printf("X509 Key Error: Invalid format\n");							break;

	default:										printf("SSL Error -0x%04x\n", -error);								break;
	}
}
