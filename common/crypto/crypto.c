#ifdef __cplusplus
extern "C" {
#endif

#include "crypto.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "crypto_proj_strings.h"
#include "polarssl/x509.h"
#include "polarssl/aes.h"
#include "dhExchange.h"

//#include "dhExchange.c"

entropy_context entropy;				// Entropy context
ctr_drbg_context ctr_drbg;				// Counter mode deterministic random byte generator context
dhm_context *dhm;						// Diffie-Hellman context
aes_context aes;						// AES context for command/control
unsigned char iv[16];					// Initialization vector
enum flag {FALSE = 0, TRUE};

enum flag encrypt = FALSE;				// AES encryption flag
enum flag rng_initialized = FALSE;		// Random number generator initialization flag

const char *personalization = "7ddc11c4-5789-44d4-8de4-88c0d23d4029";	// Custom data to add uniqueness
char *my_dhm_P = (char *) my_dhm_P_String;	// The values of these strings are located in crypto_strings.txt
char *my_dhm_G = (char *) my_dhm_G_String;
unsigned char shared_key[AES_KEY_SIZE];

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
/*!
 * @brief Initialize random number generator
 * @return
 * @retval < 0 -- error
 * @retval 1 -- success
 */
int rng_init()
{
	int ret = 1;

	DLX(6, printf( "Initializing RNG.\n"));
	if ( (ret = ctr_drbg_init(&ctr_drbg, entropy_func, &entropy, (unsigned const char *)personalization, strlen(personalization))) != 0 ) {
		DLX(4, switch (ret) {
					case POLARSSL_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED:	printf("The entropy source failed.\n"); break;
					case POLARSSL_ERR_CTR_DRBG_REQUEST_TOO_BIG:			printf("Too many random requested in single call."); break;
					case POLARSSL_ERR_CTR_DRBG_INPUT_TOO_BIG:			printf("Input too large (Entropy + additional).\n"); break;
					case POLARSSL_ERR_CTR_DRBG_FILE_IO_ERROR:			printf("Read/write error in file\n"); break;
					default:											printf("ERROR: ctr_drbg_init() failed, returned -0x%04x\n", -ret);}
				);
		if ((ret = ctr_drbg_update_seed_file(&ctr_drbg, ".seedfile")) !=0 ) {
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
	ret = ret < 0 ? ret : 1;
	ctr_drbg_set_prediction_resistance(&ctr_drbg, CTR_DRBG_PR_OFF);	// Turn off prediction resistance
	rng_initialized = TRUE;
	return ret;
}

/*!
 * gen_random
 * @brief generate random numbers
 * @param output - output buffer
 * @param output_len - length of output buffer
 * @return
 * @retval 0 -- error
 * @retval 1 -- success
 */
int gen_random(unsigned char *output, size_t output_len)
{
	if (!rng_initialized) {
		if (rng_init() < 0) {
			DLX(4, printf( "Failed to initialize random number generator\n"));
			return 0;
		}
	}

	if ((ctr_drbg_random( &ctr_drbg, output, output_len)) != 0) {
		DLX(4, printf( "Failed to generate random number\n"));
	}
	return 1;
}

//*******************************************************
/*!
 *
 * @param ssl -- SSL context
 * @return
 * @retval 0 -- error
 * @retval 1 -- success
 */
int aes_init(ssl_context *ssl) {

	int ret;

	if (ssl == NULL) {
		DLX(4, printf("failed, no SSL context.\n"));
		return 0;
	}

	DLX(4, printf( "Diffie-Hellman Handshake\n"));
	if ((dhm = dhHandshake( ssl )) == NULL)
	{
		DLX(4, printf("Diffie-Hellman Handshake failed\n"));
		return 0;
	}

	// Extract shared key from DHM context
    if ((ret = mpi_write_binary(&dhm->K, shared_key, AES_KEY_SIZE)) < 0) {
    	DLX(4, printf("mpi_write_binary() failed, returned: -0x%04x\n", ret));;
    	return 0;
    }
    DPB(4, "Shared Key", shared_key, AES_KEY_SIZE);
    md5(shared_key, AES_KEY_SIZE, iv);	// Seed initialization vector with md5 hash of shared key
    DPB(4, "Initialization Vector", iv, sizeof(iv));
    encrypt = TRUE;
    return 1;
}

int aes_terminate()
{
	if (aes.nr == 0) {
		DLX(4, printf("failed, AES context is invalid.\n"));
		return 0;
	}
	memset(&aes, 0, sizeof(aes));	// Clear the AES context
	dhm_free(dhm);
	free(dhm);
	return 1;
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
			ret = ssl_write(ssl, buf + sent, size-sent);
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
	/*!
	 * crypt_write()
	 * @param ssl -- SSL context
	 * @param buf -- buffer to transmit
	 * @param size -- size of buffer (<= 65,535 bytes)
	 * @return
	 * @retval >= 0 -- number of characters written
	 * @retval < 0  -- error
	 */
int crypt_write(ssl_context *ssl, unsigned char *buf, size_t size) {
	int ret = 0;
	size_t bufsize, sent;
	unsigned char *encbuf;

	if (size > UINT16_MAX) {	// Check size of write request
		DLX(6, printf("Size to write (%u bytes) is too big. Must be <= %u bytes\n", size, UINT16_MAX));
		return -1;
	}

	DPB(6, "Buffer to write", buf, size);
	if (encrypt) {
		DLX(6, printf("AES encrypting write buffer\n"));
		bufsize = ((size+2) % 16) ? (size+2) + (16 - (size+2)%16) : (size+2);	// Compute size of buffers - multiple of 16, including length field
		encbuf = (unsigned char *) calloc(bufsize, sizeof(unsigned char) );		// Allocate encryption buffer
		if (encbuf == NULL) {
				DLX(4, printf("calloc() failed\n"));
				return -1;
		}
	    encbuf[0] = (unsigned char)(size >> 8);	// Insert the data length
	    encbuf[1] = (unsigned char) size;
		memcpy(encbuf+2, buf, size);	// Copy input buffer to padded encryption buffer
		DPB(9, "Buffer before encryption", encbuf, bufsize);
		DPB(9, "Initialization Vector", iv, sizeof(iv));
		DLX(9, printf("aes.nr = %d\n", aes.nr));
		aes_setkey_enc(&aes, shared_key, AES_KEY_SIZE);		// Set key for encryption
		if (( ret = aes_crypt_cbc(&aes, AES_ENCRYPT, bufsize, iv, encbuf, encbuf)) < 0) {	// Encrypt the block
			DLX(4, printf("aes_crypt_cbd() failed, returned: -0x%04x\n", -ret));
			return ret;
		}
		DPB(8, "Buffer after encryption", encbuf, bufsize);
	} else {		// If not encrypting, adjust pointers
		encbuf = buf;
		bufsize = size;
	}

	DLX(8, printf("Sending %d bytes\n", bufsize));
	sent = 0;
	do {	// Write loop
		ret = ssl_write(ssl, encbuf+sent, bufsize-sent);
		if (ret < 0) {
			if (ret == POLARSSL_ERR_NET_WANT_WRITE)
				continue;

			if (ret == POLARSSL_ERR_SSL_PEER_CLOSE_NOTIFY) {
				DLX(4, printf("Remote closed connection\n"));
				break;
			}

			if (ret == POLARSSL_ERR_NET_CONN_RESET) {
				DLX(4, printf("Connection reset by peer\n"));
				break;
			}

			DLX(4, printf("ssl_write() failed, returned: -0x%04x\n", -ret));
			break;

		} else
			sent += ret;
	} while (sent < bufsize);
	DLX(7, printf("Sent %d bytes\n", sent));

	ret = (ret < 0)? ret : (int)sent; //Return the number of bytes sent or the error code
	if (encrypt)
		free(encbuf);			// Clean-up
	return ret;

}
/*!
 * @brief crypt_read - reads an ssl data stream
 * @param ssl
 * @param buf
 * @param size
 * @return
 * @retval > 0 - Number of bytes read
 * @retval 0 - EOF
 * @retval < 0 - Error
 */
//*******************************************************
int crypt_read(ssl_context *ssl, unsigned char *buf, size_t size) {
	int ret = 0, received = 0;
	size_t bufsize;
	unsigned char *encbuf;

	DL(6);
	if (encrypt) {
		bufsize = (size % 16) ? size + (16 - size%16) : size;					// Compute size of buffers - multiple of 16
		encbuf = (unsigned char *) calloc(bufsize, sizeof(unsigned char) );		// Allocate buffers
		if (encbuf == NULL) {
				DLX(4, printf("calloc() failed\n"));
				return -1;
		}
	} else {
		encbuf = buf;
		bufsize = size;
	}

	do {
		// Read data from network
		received = ssl_read(ssl, encbuf, bufsize);
		switch (received) {
			case POLARSSL_ERR_NET_WANT_READ:
				DLX(4, printf("POLARSSL_ERR_NET_WANT_READ\n"));
				continue;

			case POLARSSL_ERR_SSL_PEER_CLOSE_NOTIFY:
				DLX(4, printf("POLARSSL_ERR_SSL_PEER_CLOSE_NOTIFY\n"));
				break;

			case POLARSSL_ERR_NET_CONN_RESET:
				DLX(4, printf("Connection reset by peer\n"));
				break;

			case 0: // EOF
				if (encrypt)
					free(encbuf);
				return 0;
				break;

			default:
				if (received < 0) {
					DLX(4, printf("ERROR: crypt_read() failed. ssl_read returned -0x%04x\n", -received));
					return received;
				} else
					DLX(6, printf("%d bytes read\n", received));
				break;
		}
	} while (0);

	if (encrypt) {
		DPB(8, "Buffer before decryption", encbuf, received);
		if ( (received % 16) !=0 ) {
			DLX(6, printf("WARNING: Received data is not a multiple of 16\n"));
		}
		DLX(8, printf("AES decrypting read buffer\n"));
		DLX(9, printf("aes.nr = %d\n", aes.nr));
		DPB(9, "Initialization Vector", iv, sizeof(iv));
		aes_setkey_dec(&aes, shared_key, AES_KEY_SIZE);		// Set key for decryption
		if (( ret = aes_crypt_cbc(&aes, AES_DECRYPT, received, iv, encbuf, encbuf)) < 0) {	// Decrypt the block
			DLX(4, printf("aes_crypt_cbc() failed, returned: -0x%04x\n", -ret));
			return ret;
		}
		DPB(8, "Buffer after decryption", encbuf, received);
		bufsize = (encbuf[0] << 8) + encbuf[1];
		memcpy(buf, encbuf+2, bufsize);

		free(encbuf);
	} else {
		bufsize = received;
	}
	DPB(6, "Buffer read", buf, bufsize);
	return received;
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
