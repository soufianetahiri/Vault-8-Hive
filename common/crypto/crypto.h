#ifndef	_CRYPTO_H
#define _CRYPTO_H

#ifdef __cplusplus
extern "C" {
#endif

//*******************************************************
// used by client and server
#include "function_strings.h"
#include "polarssl/net.h"
#include "polarssl/ssl.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
#include "crypto_proj_strings.h"

#include "debug.h"

#define SRV_CERT_FILE	"./server.crt"
#define CA_CERT_FILE	"./ca.crt"
#define SRV_KEY_FILE	"./server.key"

#define CLIENT 1
#define SERVER 2

int crypt_setup_client(ssl_context *ssl, ssl_session *ssn, int *sockfd );
int crypt_setup_server(ssl_context *ssl, ssl_session *ssn, int *sockfd );
int crypt_handshake( ssl_context *ssl );
int crypt_read( ssl_context *ssl, unsigned char *buf, int bufsz );
int crypt_write( ssl_context *ssl, unsigned char *buf, int size );
int	crypt_close_notify( ssl_context *ssl );
int crypt_cleanup( ssl_context *ssl);
void print_ssl_errors(int error);
void gen_random(unsigned char *output, size_t output_len);

#ifdef __cplusplus
}
#endif

#endif	//_CRYPTO_H
